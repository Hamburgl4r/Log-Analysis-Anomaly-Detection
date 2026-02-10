import os
from preprocessing.ingest import parse
import PatternRecog 
import anomalyDetector 

def main():
    for log in parse():
