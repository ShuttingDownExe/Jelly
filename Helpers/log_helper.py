import logging

logfile = "NetLog.log"
logging.basicConfig(filename=logfile, format='%(asctime)s %(message)s', filemode='w')
logger = logging.getLogger()
