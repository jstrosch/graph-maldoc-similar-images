#!/usr/bin/env python3
#
# A script that extracts embedded images from Open Office XML (OOXML) documents and generates network
# graphs that cluster similar images together. The script computes average hashes of the extracted
# images, then graphs the images if they meet the similarity threshold. The script can be used as a
# technique for visually identifying malware campaigns involving documents. To use the script, supply
# a directory containing OOXML files. If LibreOffice is in your PATH you can optionally convert
# non-OOXML Word, Excel, PowerPoint and Rich Text File documents to OOXML. The script outputs DOT files
# that can be exported as images using Graphviz. If Graphviz is in your PATH you can also export to an
# SVG (preferred) or PNG image.
#
# Please note - for the malware signature look-up via Abuse.ch to work, the input files must be named with it's MD5 hash (no extension). If you would like to use a
# different hash, make sure to change the hash algorithm parameter for use with the Abuse.ch API.
#
# $ graph_similar_document_images.py -f <directory_containing_documents> -d <image_hash_signatures.txt> -g -t <min_similarity_threshold> -o <svg|png>
# 
# Author.....: Josh Stroschein (@jstrosch)
# Original Author.....: Alex Holland (@cryptogramfan) - https://github.com/cryptogramfan/Malware-Analysis-Scripts
# Date.......: 2020-12-30
# Version....: 0.0.1
# License....: CC BY 4.0

import os
import csv
import hashlib
import argparse
import imagehash
import subprocess
import magic
import distance
import requests
import time
import re
import json
import subprocess
import pytesseract
from PIL import Image
from termcolor import colored
from zipfile import ZipFile
from shutil import copyfileobj, copy, rmtree
from time import strftime
from networkx.algorithms import bipartite
from networkx.drawing.nx_agraph import write_dot
from networkx import graph as nx
import networkx as nkx

parser = argparse.ArgumentParser(description='\nUsage: graph_similar_document_images.py -f <directory_containing_documents> -d <image_hash_signatures.txt> -g -c -t <threshold> -o <svg|png>')
parser.add_argument('-f', '--files', dest='input_dir', help='Directory to process', required=True)
parser.add_argument('-t', '--threshold', dest='min_similarity_threshold', type=float, help='Minimum percentage similarity between images to graph (0 to 100)', default=87.5)
parser.add_argument('-d', '--detect', dest='sig_file', help='Detect mode identifies images that are similar to a blacklist of known-bad images and saves the results to a CSV (requires image_hash_signatures.txt)')
parser.add_argument('-g', '--graph', help='Graph mode creates a graph of images that meet the similarity threshold in DOT format', action='store_true')
parser.add_argument('-c', '--convert', help='Try converting documents to OOXML (requires LibreOffice)', action='store_true')
parser.add_argument('-o', '--output', choices=['svg', 'png'], help='Output image format (requires Graphviz)', default='svg')
parsed_args = parser.parse_args()
network = nx.Graph()
timestr = strftime('%Y%m%d-%H%M%S')
graph_file = 'graph_similar_document_images_' + timestr
input_dir = parsed_args.input_dir
sig_file = parsed_args.sig_file
csv_file = os.path.join(os.getcwd(), 'image_hash_matches_' + timestr + '.csv')
dir_image = os.path.join(os.getcwd(), 'extracted_document_images_' + timestr)
dir_convert_docx = os.path.join(os.getcwd(), 'convert_docx')
dir_convert_pptx = os.path.join(os.getcwd(), 'convert_pptx')
dir_convert_xlsx = os.path.join(os.getcwd(), 'convert_xlsx')
dir_converted_docx = os.path.join(os.getcwd(), 'converted_docx')
dir_converted_pptx = os.path.join(os.getcwd(), 'converted_pptx')
dir_converted_xlsx = os.path.join(os.getcwd(), 'converted_xlsx')
dir_vt_results = os.path.join(os.getcwd(), 'vt_results')
min_similarity_threshold = parsed_args.min_similarity_threshold

ocr_keywords = ['microsoft','openoffice','enable','content','editing','office']

def load_signatures():
    signatures = {}
    with open(sig_file) as f:
        for line in f:
           line = line.rstrip()
           if line:
               if not line.startswith('#'):
                   (sig_hash, sig_name) = line.split(',')
                   signatures[sig_hash] = sig_name

    return signatures

def create_dirs():
    try:
        os.makedirs(dir_convert_docx)
        os.makedirs(dir_convert_xlsx)
        os.makedirs(dir_convert_pptx)
        os.makedirs(dir_converted_docx)
        os.makedirs(dir_converted_xlsx)
        os.makedirs(dir_converted_pptx)

    except OSError:
        if not os.path.isdir(dir_convert_docx):
            raise

        if not os.path.isdir(dir_convert_xlsx):
            raise

        if not os.path.isdir(dir_convert_pptx):
            raise

        if not os.path.isdir(dir_converted_docx):
            raise

        if not os.path.isdir(dir_converted_xlsx):
            raise

        if not os.path.isdir(dir_converted_pptx):
            raise

def identify_files():
    for infile in os.listdir(input_dir):

        if os.path.isfile(os.path.join(input_dir, infile)):
            infile_path = os.path.join(input_dir, infile)
            
            if ('Microsoft OOXML' in magic.from_file(infile_path)) or ('Microsoft Word 2007+' in magic.from_file(infile_path)):
                extract_ooxml(infile_path)
            
            if parsed_args.convert:
                if ('Microsoft Office Word' in magic.from_file(infile_path)) or ('CDFV2 Encrypted' in magic.from_file(infile_path)) or ('Rich Text Format' in magic.from_file(infile_path)):
                    copy(infile_path, dir_convert_docx)

                if ('Microsoft Excel' in magic.from_file(infile_path)):
                    copy(infile_path, dir_convert_xlsx)

                if ('Microsoft Office PowerPoint' in magic.from_file(infile_path)):
                    copy(infile_path, dir_convert_pptx)
    return True

def convert_docx():
    print('\n[+] Converting to Word OOXML...')
    path = dir_convert_docx + '/*'
    
    try:    
        os.system('soffice --headless --convert-to docx --outdir ' + dir_converted_docx + ' ' + path)

    except:
        print('[!] Error converting document. Check that LibreOffice is added to your PATH.')

    print('\n[+] Extracting from converted Word OOXML documents...')
    for f in os.listdir(dir_converted_docx):
        if os.path.isfile(os.path.join(dir_converted_docx, f)):
            orig_hash = os.path.splitext(f)[0] # gets the file name w/o extension
            f = os.path.join(dir_converted_docx, f)
            extract_ooxml(f)
    
    rmtree(dir_convert_docx)
    rmtree(dir_converted_docx)
    return True
    
def convert_xlsx():
    print('\n[+] Converting to Excel OOXML...')
    path = dir_convert_xlsx + '/*'

    try:
        os.system('soffice --headless --convert-to xlsx --outdir ' + dir_converted_xlsx + ' ' + path)

    except:
        print('[!] Error converting document. Check that LibreOffice is added to your PATH.')
    
    print('\n[+] Extracting from converted Excel OOXML documents...')
    for f in os.listdir(dir_converted_xlsx):
        if os.path.isfile(os.path.join(dir_converted_xlsx, f)):
            orig_hash = os.path.splitext(f)[0] # gets the file name w/o extension
            f = os.path.join(dir_converted_xlsx, f)
            extract_ooxml(f)
    
    rmtree(dir_convert_xlsx)
    rmtree(dir_converted_xlsx)
    return True

def convert_pptx():
    print('\n[+] Converting to PowerPoint OOXML...')
    path = dir_convert_pptx + '/*'
    
    try:
        os.system('soffice --headless --convert-to pptx --outdir ' + dir_converted_pptx + ' ' + path)

    except:
        print('[!] Error converting document. Check that LibreOffice is added to your PATH.')

    print('\n[+] Extracting from converted PowerPoint OOXML documents...')
    for f in os.listdir(dir_converted_pptx):
        if os.path.isfile(os.path.join(dir_converted_pptx, f)):
            orig_hash = os.path.splitext(f)[0] # gets the file name w/o extension
            f = os.path.join(dir_converted_pptx, f)
            extract_ooxml(f)

    rmtree(dir_convert_pptx)
    rmtree(dir_converted_pptx)
    return True

def extract_ooxml(f):
    with open(f, 'rb') as infile:
        #bytes = infile.read()
        #hash_document = hashlib.sha256(bytes).hexdigest()
        hash_from_name = os.path.splitext(os.path.basename(f))[0]
        
        try:
            with ZipFile(f) as z:
                for i in z.infolist():
                    name = i.filename
                    
                    if name.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                       try:
                           image_path = os.path.join(dir_image, hash_from_name)
                           with z.open(name) as in_image, open(image_path, 'wb') as out_image:
                                copyfileobj(in_image, out_image)
                                print('[+] Extracted image from ' + f + '.')

                       except Exception as e: 
                           print('[!] Error extracting image from ' + hash_document, e)

        except Exception as e: 
            print('[!] Error unzipping ' + f, e)

def calculate_image_distance(total_docs):
    print('\n[+] Computing image hash distances...')
    images = []
    rl_results = {}
    img_ocr = {}
    
    for i in os.listdir(dir_image):
        images.append(i)

    images_a = images
    images_b = images

    # Tag lookup - Abuse.ch
    for b in images_b:
        av_label = "NONE"

        payload = {'query':'get_info','hash': str(b)}
        #print(payload)
        url = 'https://mb-api.abuse.ch/api/v1/'
        try:
            r = requests.post(url, data=payload)

            #print(r.text)

            results = json.loads(r.text)

            av_label = results["data"][0]["signature"]

            if not av_label is None:
                rl_results[b] = av_label
            else:
                rl_results[b] = "NONE"
        except:
            pass
    
    for a in images_a:
        image_a_path = os.path.join(dir_image, a)
        orig_hash = os.path.splitext(image_a_path)[0]
        hash_a = imagehash.average_hash(Image.open(image_a_path))

        try:
            img_strings = pytesseract.image_to_string(image_a_path)
            img_strings = img_strings.replace(",","").replace("."," ").replace("\n"," ")
            img_words = img_strings.split(' ')
            tmp_ocr = []

            for word in img_words:
                if len(word) >= 6 and not word in tmp_ocr:
                    tmp_ocr.append(word)
            img_ocr[a] = tmp_ocr
        except:
            pass

        for b in images_b:
            image_b_path = os.path.join(dir_image, b)
            hash_b = imagehash.average_hash(Image.open(image_b_path))
            
            image_distance = ((hash_a-hash_b)/len(hash_a.hash)**2)*100 # Each image hash is 64 bits long
            image_similarity = 100-image_distance

            if image_similarity >= min_similarity_threshold:
                print('[+] ' + a + ' is ' + str('%.0f' % image_similarity) + '% similar to ' + b + '.')

                network.add_node(a,
                        label='Image_Hash: ' + str(orig_hash) + '\n' + 'SHA256_Doc: ' + a,
                        image=image_a_path,
                        type='image',
                        style='filled',
                        fillcolor='white',
                        color='white',
                        fontcolor='black',
                        fontname='Arial',
                        fontsize='20',
                        bipartite=0)

                network.add_node(b,
                        label='Family: ' + rl_results[b] + ' Image_Hash: ' + str(hash_b) + '\n' + 'SHA256_Doc: ' + b,
                        image=image_b_path,
                        type='image',
                        style='filled',
                        fillcolor='white',
                        color='white',
                        fontcolor='black',
                        fontname='Arial',
                        fontsize='20',
                        bipartite=1)

                network.add_edge(b,
                        a,
                        penwidth=3,
                        color='#0096D6',
                        dir='none')

    connected_components = list(nkx.connected_components(network))
    number_clusters = nkx.number_connected_components(network)
    total_images = len(images)

    print("[SUMMARY]")
    print("\tNumber of Clusters: " + str(number_clusters))
    print("\tPercent Related (total docs: " + str(total_docs) + "): " + str(total_images / total_docs))

    i = 1
    for g in connected_components:
        print("[GROUP " + str(i) + "]")
        for k in g:
            try:
                print("\t" + k + " " + str(rl_results[k]))
                tmp_s = ", "
                print("\tOCR: " + tmp_s.join(img_ocr[k]))
            except:
                pass

        i = i + 1


    write_dot(network, graph_file + '.dot')
    print('[+] Created ' + graph_file + '.dot.')

    return True

def export_graph():
    try:
        if parsed_args.output == 'png':
            subprocess.Popen(['sfdp',
                            graph_file + '.dot', 
                            '-Tpng', 
                            '-o', 
                            graph_file + '.png',
                            '-Gfontname="Arial"'
                            ])
                            
            print('[+] Created ' + graph_file + '.png.')
            
        if parsed_args.output == 'svg':
            subprocess.Popen(['sfdp', 
                            graph_file + '.dot', 
                            '-Tsvg', 
                            '-o', 
                            graph_file + '.svg',
                            '-Gfontname="Arial"'
                            ])
                            
            print('[+] Created ' + graph_file + '.svg.')

    except: 
            print('[!] Error exporting graph image. Check that Graphviz is added to your PATH.')

    return True

def detect_images(signatures):
    print('\n[+] Detecting images that meet similarity threshold of signatures (' + str(parsed_args.min_similarity_threshold) + '%)...')
    images = []
    for i in os.listdir(dir_image):
        images.append(i)
    
    with open(csv_file, mode='w') as csv_out:
        csv_writer = csv.writer(csv_out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['Document_SHA256', 'Average_Hash', 'Signature_Name', 'Similarity'])
 
        for i in images:
            image_path = os.path.join(dir_image, i)
            image_hash = str(imagehash.average_hash(Image.open(image_path)))
           
            for sig_hash, sig_name in signatures.items():
                hamming_distance = distance.hamming(image_hash, sig_hash)
                image_similarity = 100-((hamming_distance/16)*100)

                if image_similarity >= min_similarity_threshold:
                    csv_writer.writerow([i, image_hash, sig_name, image_similarity])
                    print('[+] Document ' + i + ' matched ' + sig_name + ' (' + str('%.0f' % image_similarity) + '% similarity).')
    
    print('[+] Saved results to ' + csv_file + '.')    
    return True

def main():
    try:
        os.makedirs(dir_image)

    except OSError:
            if not os.path.isdir(dir_image):
                raise

    if parsed_args.convert == False:
        identify_files()

    if parsed_args.convert:
        create_dirs()
        identify_files()
        convert_docx()
        convert_xlsx()
        convert_pptx()
    
    if parsed_args.graph:
        total_docs = len(os.listdir(input_dir))

        if calculate_image_distance(total_docs):
            export_graph()

    if parsed_args.sig_file:
        signatures = load_signatures()
        detect_images(signatures)

if __name__== "__main__":
    main()
