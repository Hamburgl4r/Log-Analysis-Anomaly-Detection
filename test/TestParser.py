import pytest
import os
from src.preprocessing.LogParsers import LogParser
from src.preprocessing import FileReader 

class TestFilereader:
    def testGZIP():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.gzFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testZIP():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.TextFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testJSON():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.zipFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testTXT():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.JSONFile()
        result = reader.readFile(sample)
        assert( result == sample_result)


    def testLOG():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.logFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testCSV():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.CSVFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

class TestFilereaderFalse:

    def testGZIP():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.gzFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testZIP():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.TextFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testJSON():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.zipFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testTXT():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.JSONFile()
        result = reader.readFile(sample)
        assert( result == sample_result)


    def testLOG():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.logFile()
        result = reader.readFile(sample)
        assert( result == sample_result)

    def testCSV():
        sample_result = ""
        sample = os.path.join('path to file ')
        reader = FileReader.CSVFile()
        result = reader.readFile(sample)
        assert( result == sample_result)


class TestapacheParser:
    def test1(self):# MATCH PARSE VALUE, VALID CONFIDENCE CHECKING 
        sample = 1
        sample_value = ''
        parser = LogParser.ApacheLOGparser()

        confidence = parser.detect()

        parsed_value = parser.parseLine()
        
        assert confidence <= 0.7                                  
        assert parsed_value == sample_value   

    def test2(self): #LOW CONFIDENCE, MISSING PARSED VALUE
        sample = 1
        sample_value = ''
        parser = LogParser.ApacheLOGparser()

        confidence = parser.detect()

        parsed_value = parser.parseLine()
        
        assert confidence <= 0.7                                   
        assert parsed_value == sample_value   

    
    def test3(self): #FALSE POSSITIVE CONFIDENCE, PARSED VALUE MISMATCH
        sample = 1
        sample_value = ''
        parser = LogParser.ApacheLOGparser()

        confidence = parser.detect()

        parsed_value = parser.parseLine()
        
        assert confidence <= 0.7                                   
        assert parsed_value == sample_value   

    def test4(self): #POSSITIVE VARIANT
        sample = 1
        sample_value = ''
        parser = LogParser.ApacheLOGparser()

        confidence = parser.detect()

        parsed_value = parser.parseLine()
        
        assert confidence <= 0.7                                  
        assert parsed_value == sample_value   

    def test5(self): #NEGATIVE VARIANT
        sample = 1
        sample_value = ''
        parser = LogParser.ApacheLOGparser()

        confidence = parser.detect()

        parsed_value = parser.parseLine()
        
        assert confidence <= 0.7                                  
        assert parsed_value == sample_value  
        
         
class TestHDSFParser:

    pass
class TestdockerParser:
    pass
class TestJSONParser:
    pass
class TestSyslogParser:
    pass