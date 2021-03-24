import json
import numpy as np
from ioc_finder import find_iocs

def readJson(File):
    F = open(File,"r")
    rd = json.loads(F.read())
    F.close()
    return rd


train_data = []
tagkind = []
wrd_lst={}
def get_data():
    CVEs = readJson('full_corpus.json')
    for cve  in CVEs['MS-Bulletin']:
        text=""
        start = 0
        tag = []
        for txt in CVEs['MS-Bulletin'][cve]:
            if txt[0] not in wrd_lst.keys():
                wrd_lst[txt[0]]=txt[1]
            text+=(txt[0]+' ')
            end = start+len(txt[0])
            tag.append((start,end, txt[1]))
            if txt[1] not in tagkind:
                tagkind.append(txt[1])
            start = end + 1
            #print(text)
            #print(tag)
        train_data.append((text,{"entities":tag}))
    #add_cve_2020()
    #print(tagkind)




def get_key(txt,ioc):
    txt = txt.replace(" ", "")
    k = 'O'
    for key in ioc:
        #print(key)
        #print(ioc[key])
        if (txt in ioc[key]):
            #print(key)
            k = key
            break
    return k

def ioc_tagging():
    CVEs = readJson('/Users/parvez/Desktop/Fal2020/IndStudy/Diff_static_ana/NVD_2020/nvdcve-1.1-2020.json')
    cve_itm = CVEs['CVE_Items']
    print(len(cve_itm))
    for i,tag in enumerate(cve_itm):
        text=cve_itm[i]['cve']['description']['description_data'][0]['value']
        #text = "google did a buffer-overflow attack for bitcoin using abc.java using android os and phone number: +1402805697 and email abc.hotmail.com https://www.codegrepper.com/code-examples/delphi/get+key+name+from+dictionary+python"
        entr= []
        txt_lst = text.split(' ')
        iocs = find_iocs(text)
        tag=[]
        start=0
        for wrd in txt_lst:
            end = start + len(wrd)-1
            if wrd not in wrd_lst.keys():
                k=get_key(wrd,iocs)

                if k !='O':
                    tag.append((start, end, k))
                else:
                    tag.append((start, end, 'O'))
            else:
                tag.append((start, end, wrd_lst[wrd]))


            start = end+2
        print(i)
        print((text, {"entities": tag}))
        train_data.append((text, {"entities": tag}))
        with open('ner_tags.csv', mode='a') as file_:
            file_.write("{}".format((text, {"entities": tag})))
            file_.write("\n")




def get_labelled_sent():
    get_data()
    ioc_tagging()

    return train_data

