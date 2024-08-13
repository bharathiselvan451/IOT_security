import urllib.request
import json
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen
import requests
from datetime import date
from tqdm import tqdm
import platform



file = input("Enter the directory of the logs - ")


if(platform.system()=="Darwin"):
    file = file+"/f20_vul_aggregator/exploits-overview.txt"
elif(platform.system()=="Windows"):
    file = file+"\f20_vul_aggregator\exploits-overview.txt"
else:
    file = file+"/f20_vul_aggregator/exploits-overview.txt"



#infile = r"/Users/divyaprabharajendran/Downloads/logs/f20_vul_aggregator/exploits-overview.txt"

sets = set()
keep_phrases = ["Exploit"]

with open(file) as f:
    f = f.readlines()

for line in f:
    for phrase in keep_phrases:
        if phrase in line:
            
            try:
                if(line.split(":")[1].strip()=="2.6.30.9"):
                   sets.add(line)
            except:
                continue
            break
print("*************")



current_date = date.today()
current_year = current_date.year


year  = 2002

with tqdm(total=current_year-year) as pbar:
 while (year<=current_year):
          
          url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+str(year)+".json.zip"
          #resp = requests.get(url).content()
          resp = urlopen(url)
          myzip = ZipFile(BytesIO(resp.read()))
          myzip.extractall(path='jsons')
          year = year+1
          pbar.update(1)

#pbar.close()
print(" ")
json_data = []
for val in tqdm(sets):
      try:
         cve = val.split(":")[2].strip()
         if((int(str(cve).split('-')[1]))>2002):
             f = open('jsons/nvdcve-1.1-'+str(cve).split('-')[1]+'.json')
         else:
             f = open('jsons/nvdcve-1.1-2002.json')

          
         data = json.loads(f.read())
         i = 0
         while(True):
    
           if(data["CVE_Items"][i]['cve']['CVE_data_meta']['ID']==str(cve)):
              cve_id = (data["CVE_Items"][i]['cve']['CVE_data_meta']['ID'])
              desc = (data["CVE_Items"][i]['cve']['description']['description_data'][0]['value'])
              url = ""
              count = 0
              while(len(data["CVE_Items"][i]['cve']['references']['reference_data'])>count):
                 count_2 = 0
                 
                 while(len(data["CVE_Items"][i]['cve']['references']['reference_data'][count]['tags'])>count_2):
                     if((data["CVE_Items"][i]['cve']['references']['reference_data'][count]['tags'][count_2])=="Patch"):
                         url = url+(data["CVE_Items"][i]['cve']['references']['reference_data'][count]['url'])+", "
                     count_2 = count_2+1
                 count = count+1
              if(len(url)==0):
                url = "No official patch available"
              dict = {}
              dict["CVE_ID"]= cve_id
              dict["Discription"]= desc
              dict["url"]= url
              #print(dict)
              json_data.append(dict)
              #print(dict)
              break
           i = i+1
           

      except:
           continue
final_file = json.dumps(json_data)

path = input("Path to save the results - ")

with open(path+"/result.json", "w") as outfile:
    outfile.write(final_file)

