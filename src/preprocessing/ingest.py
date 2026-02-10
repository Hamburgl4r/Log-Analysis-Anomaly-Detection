import os
from FileReader import TextFile,JSONFile,gzFile,zipFile,logFile,CSVFile,ReaderContext
from LogParser.LogParser import ParserContext,ApacheLOGparser,JSONparser,SYSLOGparser,DOCKERparser,HDFSparser


def RetrieveLogFiles(folderPath=os.path.join(os.getcwd(), "logfiles")):
    logFilePaths = []
    for name in os.listdir(folderPath):
        full_path = os.path.join(folderPath, name)
        if os.path.isfile(full_path):
            logFilePaths.append(full_path)

    return logFilePaths

#on notice
def parse():
    #called from outside of class, facade to hide the inner working of the FileParser.py
    #enter called RetrieveLogFiles -> read the file -> parse the files -> return dict of content mapping (JSON format)
    try:
        logFiles = RetrieveLogFiles()
        for files in logFiles:
            with open(files,"r") as f:
                pass
            f.close()
    except Exception as e:
        raise e
    
    readerStrategies = [TextFile,JSONFile,gzFile,zipFile,logFile,CSVFile]
    parserstrategies = [ApacheLOGparser,JSONparser,SYSLOGparser,DOCKERparser,HDFSparser]
    parser = ParserContext(parserstrategies)
    reader = ReaderContext(readerStrategies)


    for filepath in logFiles:
        
        if reader.canHandle(filepath):
            lines = reader.readFile(filepath)
            lines_length = len(lines)
        else:
            continue
        bParser, confidence = parser.detect((lines_length/2)[:])
        for line in lines:
            if line:
                
                parser.setParser(bParser)
                try:
                    yield from parser.parse(line)
                    print("Confidence level: " + confidence)
                    print("Format: ")
                    print("Length: " +len(line))
                except Exception as e:
                    print(f"Failed to parse; Exception {e} encountered")
                    continue

    print("Successful parse")
