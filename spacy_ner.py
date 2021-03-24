import plac
import random
from pathlib import Path
import spacy
from spacy.util import minibatch, compounding
import data_process

#TRAIN_DATA = data_process.get_labelled_sent()
#Train model
'''def make_model():
    nlp = spacy.blank("en")
    ner = nlp.create_pipe("ner")
    nlp.add_pipe(ner, last=True)

    for txt, annt in TRAIN_DATA:
        for entts in annt.get("entities"):
            ner.add_label(entts[2])

    nlp.begin_training()
    for c in range(10):
        random.shuffle(TRAIN_DATA)
        loss = {}
        batches = minibatch(TRAIN_DATA, size=compounding(4.0, 32.0, 1.001))
        for batch in batches:
            txts, annts = zip(*batch)
            nlp.update(txts,annts,drop=0.5,losses=loss,)
            print("Losses", loss)
    nlp.to_disk(Path('./Model'))

make_model()'''
#load model
nlp2 = spacy.load(Path('./Model'))

doc = nlp2("MThe kubectl cp command allows copying files between containers and the user machine. To copy files from a container, Kubernetes creates a tar inside the container, copies it over the network, and kubectl unpacks it on the user’s machine. If the tar binary in the container is malicious, it could run any code and output unexpected, malicious results. An attacker could use this to write files to any path on the user’s machine when kubectl cp is called, limited only by the system permissions of the local user. Since fixing CVE-2018-1002100, the untar function calls the cp.go:clean to strip path traversals. However, that function can both create and follow symbolic links")
print("Entities", [(ent.text, ent.label_) for ent in doc.ents])








