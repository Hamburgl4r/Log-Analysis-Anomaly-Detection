import os
from abc import ABC,abstractmethod
from importlib.util import source_hash
from operator import truediv
import gzip
import zipfile as z
import csv
import json
import re
from datetime import datetime
from tkinter import EventType
import pandas as pd



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
        elif status >= 400:
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
        if not sample:
            return 0.0
        
        sample1 = [line for line in sample if line.strip()]

        if not sample1:
            return 0.0
        
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
        return score / totalLines


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

        sample1 = [line for line in sample if line.strip()]

        if not sample1:
            return 0.0

        for line in sample:
            lineScore = 0.0
            if re.match(r'^\d{6}\s\d{6}', line):
                lineScore +=0.35

            if any(keyword in line for keyword in ["DataNode", "NameNode", "dfs.", "blk_"]):
                lineScore += 0.4

            if re.search(r"\[\d+\]", line):
                lineScore +=0.15

            if ':' in line:
                lineScore += 0.1

            score += min(lineScore, 1.0)

        return score / totalLength


        

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

        sample1 = [line for line in sample if line.strip()]

        if not sample1:
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

        return score / total_len




class DOCKERparser(fileParser):

    #fields: log, stream, time
    def parseLine(self,line):
        if not line:
            return None 
        
        try:
            data = json.loads(line)
        except:
            return None
        
        #check for correct formated log field

        #check for correct formated stream (output media)

        #check for correct formated time stamp and time stamp format

        #check if in the above order


        if "log" not in data:
            return None
        
        if "stream" not in data:
            return None
        
        if "time" not in data:
            return None 
        

        if data["log"] == None or data["time"]==None:
            return None

        try:
            dt_object = datetime.fromisoformat(data["time"])
        except:
            dt_object.replace("Z","+00:00")
            try:
                dt_object = pd.to_datetime(data["time"])
            except:
                return None
            
        log = data["log"].strip()
        
        pattern = re.compile(r'\[?(INFO|WARN|ERROR)\]?:?')

        match = pattern.search(log)
        log_level = match.group(0) if match else None
        
        stream = data['stream']
        if not log_level:
            if stream == 'stderr':
                log_level = "ERROR"

        eventtypefields = {"info": "docker_log", "error": "docker_error", "warn": "docker_warn"}

        eventtype = next((v for k, v in eventtypefields.items() if k in log_level.lower()), None)

        
        if log_level:
            msg  = log.split(log_level)[1]
            
        msg = log



        if len(data) > 3:
            remaining_fields = data.keys()[3:]

        return {
            'message': msg,
            'level':log_level,
            "time": dt_object if dt_object else None,
            'source':"Docker",
            'event_type': eventtype,
            'raw message': log,
            'metadata':{
                {key: data[key] for key in remaining_fields}
            }

        }
 


    def detectConfidence(self,sample):
        score = 0.0
        total_lines = len(sample)

        if not sample:
            return 0.0
        
        sample1 = [line for line in sample if line.strip()]

        if not sample1:
            return 0.0
        
        if total_lines == 0:
            return 0.0
        
        for line in sample:
            line = line.strip()

            if line.startswith("{") and line.endswith("}"):
                score +=0.01
                try:
                    data =  json.loads(line)
                    for fields in ["log","stream","time"]:
                        if fields in data:
                            score +=0.33

                except:
                    return 0.0   
                
           

        return score / total_lines
    

class JSONparser(fileParser):
    def parseLine(self,line):
        if not line:
            return None

        try:
            data = json.loads(line)
        except:
            return None
        
        match = re.search(r'\b')
        timestamp_fields = ["timestamp", "time", "@timestamp", "datetime", "date"]

        timestamp_value = next((data[field] for field in timestamp_fields if field in data),None)

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
        msg = next((str(data[field]) for field in msg_field if field in data),None)


        source_field = ["service", "source", "component", "logger", "name"]
        source = next((str(data[field]) for field in source_field if field in data),None)

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
            "metadata": metadata,
            "raw_message": line.strip()
        }


    def detectConfidence(self,sample):
        score = 0.0
        total_lines = len(sample)

        if not sample:
            return 0.0
        
        sample1 = [line for line in sample if line.strip()]

        if not sample1:
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
                    score = 0.0

            else:
                score = 0.0

        return score / total_lines


class ParserContext:
    def __init__(self, parsers:list[fileParser]):
        self.parsers = parsers
        self.parser = None

    def setParser(self,parser):
        self.parser = parser

    def parse(self,line):
        yield from self.parser.parseLine(line)

    def detect(self,sample):
        confidence = 0.0
        bestParser = None
        for parser in self.parsers:
            curConf = parser.detectConfidence(sample)
            if curConf > confidence:
                confidence = curConf
                bestParser = parser
        return bestParser, confidence


