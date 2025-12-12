import os
from abc import ABC,abstractmethod
from operator import truediv
import gzip
import zipfile
import csv
import json

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



class fileParser(ABC):
    @abstractmethod
    def parsefile(self):
        pass
    @abstractmethod
    def detectConfidence(self):
        pass

    @abstractmethod
    def getMetadata(self):
        pass

    def validate(self):
        return True

class fileIn:
    def __init__(self):
        '''

        :param path: directory containing all the log files
        '''
        self._filepath = os.join(os.path.dirname(__file__), "LogFiles")
        self._fileTypes = [] #contains a list of the file types given in the log files
        self._fileContents = {} #key = file names

    def loadFiles(self):
        dir = os.listdir(self._filepath)

        for line in dir:
            self._fileTypes.append(line.split(".",1)[1])
            with open(line, 'r') as File:
                self._fileContents[line] = File.readlines()


    def getFileType(self):
        return self._fileTypes

    def getFileDict(self):
        return self._fileContents

class contextParser:

    def __init__(self, parseStrat: fileParser = None):
        self._strategy = parseStrat
        self._allstrats = self.loadStrategies()

    def loadStrategies(self,type):
        match type:
            case "gz":
                pass
            case "log":
                pass
            case "zip":
                pass
            case "csv":
                pass
            case _:
                return 0