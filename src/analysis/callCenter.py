import os
from preprocessing.ingest import parse
import PatternRecog as pr
import anomalyDetector as ad

def main():
    for log in parse():
        #call pattern learner/match 
        pass
        #condition to detector file checks to match if patterns have meaning or anysort

        #recursively feed detector results to pattern learner. this is subject to change depending on structure of both files


