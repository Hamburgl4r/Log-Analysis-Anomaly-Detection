import os
from abc import ABC,abstractmethod
from importlib.util import source_hash
from operator import truediv
import gzip
import zipfile as z
import csv
import json


class fileReader(ABC):
    @abstractmethod
    def readFile(self,filepath:str):
        pass

    @abstractmethod
    def canHandle(self,filepath:str):
        pass

class TextFile(fileReader):
    def readFile(self,filepath):
        if self.canHandle(filepath):
            with open(filepath, 'r',encoding='utf-8', errors='ignore') as f:
                for line in f.readlines():
                    yield line.strip()

    def canHandle(self,filepath):
        return filepath.endswith(".txt")

class gzFile(fileReader):
    def readFile(self,filepath):
        if self.canHandle(filepath):
            with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as z:
                for file in z:
                    yield file.strip()

    def canHandle(self,filepath):
        return filepath.endswith(".gz")

class zipFile(fileReader):
    def readFile(self,filepath):
        if self.canHandle(filepath):
            with z.ZipFile(filepath,"r") as z:
                for f in z.namelist():
                    with z.open(f,"r") as file:
                        for line in file:
                            yield line.decode('utf-8', errors='ignore').strip()
    def canHandle(self,filepath:str):
        return filepath.endswith(".zip")

class logFile(fileReader):
    def readFile(self,filepath:str):
        if self.canHandle(filepath):
            with open(filepath, 'r',encoding='utf-8', errors='ignore') as f:
                for line in f.readlines():
                    yield line.strip()

    def canHandle(self,filepath:str):
        return filepath.endswith(".log")
    

class JSONFile(fileReader):

    def readFile(self,filepath:str):

        if self.canHandle(filepath):

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as json:
                for line in json:
                    try:
                        obj = json.loads(line.strip())
                        yield json.dumps(obj)
                    except json.JSONDecodeError:
                        yield line.strip()


    def canHandle(self,filepath:str):
        return filepath.endswith(".json")
    
class CSVFile(fileReader):
    def readFile(self,filepath:str):

        if self.canHandle(filepath):

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for line in reader:
                    #join elements of the csv contents into one singular line
                    yield ', '.join(f"{k}={v}" for k, v in line.items())

    def canHandle(self,filepath:str):
        return filepath.endswith(".csv")


class ReaderContext:
    def __init__(self, fileReaderStrategy: list[fileReader]):
        self.readers = fileReaderStrategy
        self.reader = None

    def setFileReaderStrategy(self,reader:fileReader):
        self.reader = reader

    def readFile(self,filepath):
        self.reader.readFile(filepath)

    def canHandle(self,filename:str):
        for reader in self.readers:
            if reader.canHandle(filename):
                self.setFileReaderStrategy(reader)
                return 1
        return 0