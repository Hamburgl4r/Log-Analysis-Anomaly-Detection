import os
from abc import ABC,abstractmethod




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