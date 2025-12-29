import os
from abc import ABC,abstractmethod
from importlib.util import source_hash
from operator import truediv
import gzip
import zipfile
import csv
import json
import re
from datetime import datetime
from tkinter import EventType


class fileReader(ABC):
    @abstractmethod
    def readFile(self,filepath:str):
        pass

    @abstractmethod
    def canHandle(self,filepath:str):
        pass

class Textfile(fileReader):
    def readFile(self,filepath):
        if self.canHandle(filepath):
            with open(filepath, 'r',encoding='utf-8', errors='ignore') as f:
                for line in f.readlines():
                    yield line.strip()

    def canHandle(self,filepath):
        filetype = filepath.split(".")[1]
        if filetype == "txt":
            return True

class gzfile(fileReader):
    def readFile(self,filepath):
        if self.canRead(filepath):
            with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as z:
                for file in z:
                    yield file.strip()

    def canRead(self,filepath):
        if filepath.endswith(".gz"):
            return True

class zipfile(fileReader):
    def readFile(self,filepath):
        if self.canHandle(filepath):
            with zipfile.ZipFile(filepath,"r") as z:
                for f in z.namelist():
                    with z.open(f,"r") as file:
                        for line in file:
                            yield line.decode('utf-8', errors='ignore').strip()
    def canHandle(self,filepath:str):
        if filepath.endswith(".zip"):
            return True

class logfile(fileReader):
    def readFile(self,filepath:str):
        if self.canHandle(filepath):
            with open(filepath, 'r',encoding='utf-8', errors='ignore') as f:
                for line in f.readlines():
                    yield line.strip()

    def canHandle(self,filepath:str):
        return filepath.endswith(".log")

class JSONfile(fileReader):

    def readFile(self,filepath:str):

        if self.canHandle(filepath):

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as json:
                for line in json:
                    try:
                        obj = json.load(line.strip())
                        yield json.dumps(obj)
                    except json.JSONDecodeError:
                        yield line.strip()


    def canHandle(self,filepath:str):
        if filepath.endswith(".json"):
            return True

class CSVfile(fileReader):
    def readFile(self,filepath:str):

        if self.canHandle(filepath):

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as csv:
                reader = csv.DictReader(csv)

                for line in reader:
                    #join elements of the csv contents into one singular line
                    yield ', '.join(f"{k}={v}" for k, v in line.items())

    def canHandle(self,filepath:str):
        if filepath.endswith(".csv"):
            return True


class ReaderContext:
    def __init__(self, fileReaderStrategy:fileReader = None):
        self.reader = fileReaderStrategy

    def setFileReaderStrategy(self,fileReaderStrategy:fileReader):
        self.reader = fileReaderStrategy

    def readFile(self,filepath):
        self.reader.readFile(filepath)



class fileParser(ABC):
    @abstractmethod
    def parseLine(self):#parse and extract the raw line for metadata
        pass
    @abstractmethod
    def detectConfidence(self):#check whether the current line is should use this parser type
        pass


    def getMetadata(self):
        return {
            'name': self.__class__.__name__,
            'description': self.__doc__ or 'No description',
            'supported_formats': getattr(self, 'SUPPORTED_FORMATS', []),
            'confidence_threshold': getattr(self, 'CONFIDENCE_THRESHOLD', 0.7)
        }


    def parsedata(self, lines: list[str]):
        parsed_logs = []
        for line_num, line in enumerate(lines, 1):
            try:
                parsed = self.parse_line(line)
                if parsed:
                    parsed_logs.append(parsed)
            except Exception as e:
                # Log error but continue parsing
                print(f"Error parsing line {line_num}: {e}")
                continue

        return parsed_logs

    def validate(self):
        return True



class ApacheLOGparser(fileParser):
    ### below is the formatting for this apache log format and its respective encoding
    SUPPORTED_FORMATS = ['apache_common', 'apache_combined', 'nginx']
    CONFIDENCE_THRESHOLD = 0.7

    COMMON_LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) '                              # IP address
        r'\S+ '                                       # ident (ignore)
        r'\S+ '                                       # authuser (ignore)
        r'\[(?P<timestamp>[^\]]+)\] '                # timestamp
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '  # request
        r'(?P<status>\d{3}) '                        # status code
        r'(?P<size>\S+)'                             # response size
    )

    COMBINED_LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) '
        r'\S+ \S+ '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
        r'(?P<status>\d{3}) '
        r'(?P<size>\S+) '
        r'"(?P<referer>[^"]*)" '                     # referer
        r'"(?P<user_agent>[^"]*)"'                   # user agent
    )


    def parseLine(self,line):
        if not line.strip():
            return None

        content = self.COMBINED_LOG_PATTERN.match(line)
        if not content:
            content = self.COMMON_LOG_PATTERN.match(line)
            if not content:
                return None



        data = content.groupdict()

        timestamp = None
        try:
            timestamp = datetime.strptime(data['timestamp'].split()[0],'%d/%b/%Y:%H:%M:%S')
        except ValueError:
            pass

        try:
            size = int(data['size']) if data['size'] != '-' else 0
        except (ValueError, KeyError):
            size = 0

        status = int(data['status'])
        level = None
        if status >= 500:
            level = "ERROR"
            EventType = "http_server_error"
        if status >= 400:
            level = "WARN"
            EventType = "http_client_error"
        else:
            EventType = "http_request"

        parsed = {
            'timestamp': timestamp,
            'raw_message': line.strip(),
            'level': level,
            'source': data['ip'],
            'event_type': EventType,
            'message': f"{data['method']} {data['path']} {data['protocol']}",
            'metadata': {
                'http_method': data['method'],
                'path': data['path'],
                'http_version': data['protocol'],
                'status_code': status,
                'response_size': size,
            }
        }

        if 'referer' in data:
            parsed['metadata']['referer'] = data['referer']
        if 'user_agent' in data:
            parsed['metadata']['user_agent'] = data['user_agent']

        return parsed


    def detectConfidence(self,sample: list[str]):
        score = 0.0
        totalLines = len(sample)

        if totalLines == 0:
            return 0.0

        for lines in sample:
            lineScore = 0.0

            if re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', lines):
                lineScore += 0.3
            # Check for HTTP version
            if re.search(r'HTTP/\d\.\d', lines):
                lineScore += 0.3

            # Check for status code
            if re.search(r'\s\d{3}\s', lines):
                lineScore += 0.2

            # Check for timestamp in brackets
            if re.search(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', lines):
                lineScore += 0.2

            score += min(lineScore, 1.0)

        # Return average score
        return score / lineScore


class HDFSparser(fileParser):

    HDFS_PATTERN = re.compile(
        r'(?P<date>\d{6})\s+'        # YYMMDD (081109)
        r'(?P<time>\d{6})\s+'        # HHMMSS (203615)
        r'(?P<thread>\d+)\s+'        # Thread ID (148)
        r'(?P<level>\w+)\s+'         # Level (INFO, WARN, ERROR)
        r'(?P<component>[\w.$]+):\s*'  # Component (dfs.DataNode)
        r'(?P<message>.*)'           # Message
    )


    def parseLine(self,line):
        if not line.strip():
            return None

        content = self.HDFS_PATTERN.match(line)
        if not content:
            return None

        data = content.groupdict()

        date = data['date']         # '081109'
        time = data['time']         # '203615'
        thread = data['thread']     # '148'
        level = data['level']       # 'INFO'
        component = data['component']  # 'dfs.DataNode$PacketResponder'
        message = data['message']


        datetime_str = date + time

        try:
            timestamp = datetime.strptime(datetime_str, '%y%m%d%H%M%S')
        except ValueError:
            timestamp = None

        block_match = re.search(r'blk_-?\d+', message)
        if block_match:
            block_id = block_match.group()
        else:
            block_id = None

        message_lower = message.lower()

        if 'terminating' in message_lower or 'shutdown' in message_lower:
            event_type = 'component_shutdown'
        elif 'received' in message_lower:
            event_type = 'block_received'
        elif 'error' in message_lower or 'exception' in message_lower:
            event_type = 'error'
        else:
            event_type = 'hdfs_event'

        parsed = {
            'timestamp': timestamp,
            'raw_message': line.strip(),
            'level': level,           # Already explicit in HDFS logs
            'source': component,
            'event_type': event_type,
            'message': message,
            'metadata': {
                'thread_id': int(thread),
                'component': component,
                'block_id': block_id  # Might be None
            }
        }

        return parsed


    def detectConfidence(self,sample):
        score = 0.0
        totalLength = len(sample)

        if not sample:
            return 0.0

        sample = [line for line in sample if line.strip()]

        if not sample:
            return 0.0

        for line in sample:
            lineScore = 0.0
            if re.match(r'^\d{6}\s\d{6}', line):
                lineScore +=0.35

            if line.contains("DataNode", "NameNode", "dfs.", "blk_"):
                lineScore += 0.4

            if re.search(r"\[\d+\]", line):
                lineScore +=0.15

            if ':' in line:
                lineScore += 0.1

            score += min(lineScore, 1.0)

        return score / lineScore


        

class SYSLOGparser(fileParser):
    SUPPORTED_FORMATS = ['syslog', 'rsyslog', 'syslog-ng']
    CONFIDENCE_THRESHOLD = 0.7


    SYSLOG_PATTERN = re.compile(
        r'(\w{3})' +              # Month
        r'\s+(\d{1,2})' +         # Day
        r'\s+(\d{2}:\d{2}:\d{2})' +  # Time
        r'\s+(\S+)' +             # Hostname
        r'\s+(\S+?)' +            # Service
        r'(\[(\d+)\])?' +         # Optional [PID]
        r'\s*:\s*' +              # Colon separator (with optional spaces)
        r'(.*)'                   # Message
    )

    COMBINED_SYSLOG_PATTERN = re.compile(
        r'(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(\[(\d+)\])?\s*:\s*(.*)'
    )


    def parseLine(self,line:str):
        if not line.strip():
            return None
        content = self.COMBINED_SYSLOG_PATTERN.match(line)
        if not content:
            content = self.SYSLOG_PATTERN.match(line)
            if not content:
                return None

        month = content.group(1)
        day = content.group(2)
        time = content.group(3)
        hostname = content.group(4)
        service = content.group(5)
        pid = content.group(7)
        message = content.group(8)

        data = content.groupdict()

        current_year = datetime.now().year
        timestamp_str = f"{month} {day} {time} {current_year}"

        try:
            timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S %Y')
        except ValueError:
            timestamp = None

        message_lower = message.lower()


        if any(keyword in message_lower for keyword in ['error', 'fail', 'fatal', 'critical']):
            level = 'ERROR'
        elif any(keyword in message_lower for keyword in ['warn', 'warning']):
            level = 'WARN'
        elif any(keyword in message_lower for keyword in ['info', 'notice']):
            level = 'INFO'
        elif 'debug' in message_lower:
            level = 'DEBUG'
        else:
            level = None


        if service.startswith('ssh'):
            if 'failed' in message_lower or 'invalid' in message_lower:
                event_type = 'auth_failure'
            elif 'accepted' in message_lower:
                event_type = 'auth_success'
            else:
                event_type = 'ssh_event'
        elif service in ['systemd', 'kernel']:
            event_type = 'system_event'
        else:
            event_type = 'generic_event'


        parsed = {
            'timestamp': timestamp,
            'raw_message': line.strip(),
            'level': level,
            'source': service,
            'event_type': event_type,
            'message': message,
            'metadata': {
                'hostname': hostname,
                'service': service,
                'pid': int(pid) if pid else None
            }

        }
        return parsed

    def detectConfidence(self,sample):
        score = 0.0

        if not sample:
            return 0.0

        sample = [line for line in sample if line.strip()]

        if not sample:
            return 0.0

        total_len = len(sample)


        for line in sample:
            lineScore = 0.0

            if re.match(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
                lineScore += 0.4

            if re.search(r'\w+\[\d+\]', line):
                lineScore += 0.3

            if re.search(r'\b(INFO|DEBUG|WARN|ERROR)\b',line):
                lineScore += 0.3

            syslog_services = ['sshd', 'systemd', 'kernel', 'cron', 'sudo', 'nginx']
            if any(service in line.lower() for service in syslog_services):
                lineScore += 0.2

            if ':' in line:
                lineScore += 0.1

            score += min(lineScore, 1.0)

        return score / lineScore




class DOCKERparser(fileParser):

    def parseLine(self,line):

    def detectConfidence(self):



class JSONparser(fileParser):
    def parseLine(self,line):
        if not line:
            return None

        try:
            data = json.loads(line)
        except:
            return None

        timestamp_fields = ["timestamp", "time", "@timestamp", "datetime", "date"]

        timestamp_value = None
        for field in timestamp_fields:
            if field in data:
                timestamp_value = data[field]
                break

        if timestamp_value is None:
            return None

        if isinstance(timestamp_value, str):#ISO parse attempt
            try:
                timestamp_value = datetime.fromisoformat(timestamp_value.replace("Z","+00:00"))
            except:
                pass

        elif isinstance(timestamp_value,(int,float)):#unix(seconds) parse attempt
            try:
                if timestamp_value <10000000000:
                    timestamp_value = datetime.fromtimestamp(timestamp_value)
                else:
                    timestamp_value = datetime.fromtimestamp(timestamp_value / 1000)
            except:
                pass


        if not isinstance(timestamp_value, datetime):
            timestamp_value = None

        level_fields = ["level", "severity", "log_level", "loglevel"]

        level = None
        for field in level_fields:
            if field in data:
                level = data[field]
                level = str(level.upper())
                break

        msg_field = ["message", "msg", "text", "log"]
        msg = None
        for field in msg_field:
            if field in data:
                msg = str(data[field])
                break

        source_field = ["service", "source", "component", "logger", "name"]
        source = None
        for field in source_field:
            if field in data:
                source = str(data[field])
                break
        eventType = "json_event"

        if "event_type" in data:
            eventType = data["event_type"]
        elif "event" in data:
            eventType = data["event"]

        exclude_fields = {
            "timestamp", "time", "@timestamp", "datetime", "date",
            "level", "severity", "log_level", "loglevel",
            "message", "msg", "text", "log",
            "service", "source", "component", "logger", "name",
            "event_type", "event"
        }
        metadata = {key: value for key, value in data.items() if key not in exclude_fields}

        return {
            "timestamp": timestamp_value,
            "level": level,
            "message": msg,
            "source": source,
            "event_type": eventType,
            "metadata": metadata
        }


    def detectConfidence(self,sample):
        score = 0.0
        total_lines = len(sample)

        if not sample:
            return 0.0

        if total_lines == 0:
            return 0.0

        for line in sample:
            line = line.strip()

            if line.startswith('{') and line.endswith('}'):

                try:
                    json.loads(line)
                    score += 1.0
                except json.JSONDecodeError:
                    score += 0.0

            else:
                score += 0.0

        return score / total_lines


class ParserContext:
    def __init__(self, parsers =fileParser):
        self.parser = parseStrategy

    def setParseStrategy(self,parseStategy):
        self.parser = parseStategy

    def parse(self):
        self.parser.parseLine()


def RetrieveLogFiles(folderPath=os.path.join(os.getcwd(), "logfiles")):
    logFilePaths = []
    for name in os.listdir(folderPath):
        full_path = os.path.join(folderPath, name)
        if os.path.isfile(full_path):
            logFilePaths.append(full_path)

    return logFilePaths


class FileIn:
    pass

def parse() -> dict:
    #called from outside of class, facade to hide the inner working of the FileParser.py
    #enter called RetrieveLogFiles -> read the file -> parse the files -> return dict of content mapping (JSON format)


def main():
    pass

if __name__ == "__main__":

    main()