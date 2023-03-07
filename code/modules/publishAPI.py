from flask import Flask
from flask import request
from datetime import datetime
from file_read_backwards import FileReadBackwards
import json


app = Flask(__name__)

config = open("config.json").read()
config = json.loads(config)
list_of_nodes = config['nodes']
infile = config['logfilepath']
apikey = config['apikey'][0]

def process_response(logdata_lines):
   response = []

   for line in logdata_lines:
      line = line.replace("\n", "")+"\n"
      if( '"cowrie.command.input","input":""' in line ):
         continue
      line = line.replace("cowrie","iotac.honeypot")
      line_obj = json.loads(line)
      line = json.dumps(line_obj)+"\n"
      response.append(line)

   return ((''.join(response))+"\n")


# curl -k https://172.17.0.2:5000/getall --header "apikey: iotacAPIkey1-s56JkyKbk4WrSBaXt9M99PC9XpGtUKZu9T"
@app.route('/getall')
def get_full_log():
   keyrequested = request.headers.get('apikey')
   if(keyrequested != apikey):
      return "invalid api key\n"
   try:
      logdata = open(infile, "r").readlines()
      return process_response(logdata)
   except Exception as e:
      return "error loading log data\n"#+str(e)


# curl -k https://172.17.0.2:5000/getlatest?lastdate=2021-11-17T14:40:34 --header "apikey: iotacAPIkey1-s56JkyKbk4WrSBaXt9M99PC9XpGtUKZu9T"
@app.route('/getlatest', methods=['GET', 'POST'])
def log():
   keyrequested = request.headers.get('apikey')
   if(keyrequested != apikey):
      return "invalid api key\n"

   maxtime = request.args.get('lastdate')
   print (maxtime)
   if not (maxtime):
      return ("malformed request, use /getlatest?lastdateYYYY-MM-DDTHH:MM:SS\n")
   if (maxtime):
      try:
         reqtime_obj = datetime.strptime(maxtime, '%Y-%m-%dT%H:%M:%S')
      except Exception as e:
         return ("malformed request, use /getlatest?lastdateYYYY-MM-DDTHH:MM:SS\n")

   try:
      with FileReadBackwards(infile, encoding="utf-8") as reversefile:
         logdata = []
         for line in reversefile:
            log_obj = json.loads(line)
            line_time_str = log_obj['timestamp'].split(".")[0]
            log_time_obj = datetime.strptime(line_time_str, '%Y-%m-%dT%H:%M:%S')
            
            # add some filters for unnessessary entries
            if(reqtime_obj < log_time_obj):
               logdata.append( line )

         if(len(logdata) == 0):
            return ("nothing new since "+str(maxtime)+"\n")
         
         return process_response( logdata[::-1] )
      
   except Exception as e:
      return "error loading log data\n"+str(e)

   return "error" # should never happen



if __name__ == '__main__':
   app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')










