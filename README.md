# Graph Similar Maldoc Images
 A script that extracts embedded images from [Office Open XML (OOXML)](https://en.wikipedia.org/wiki/Office_Open_XML) documents and generates image hash similarity graphs that cluster visually similar images together. The script computes the [Average Hash](http://www.hackerfactor.com/blog/index.php?/archives/432-Looks-Like-It.html) of each extracted image, then graphs the images if they meet the similarity threshold. The script can be used as a technique for visually identifying malware campaigns involving documents. To use the script, supply a directory containing OOXML files. If LibreOffice is in your PATH you can optionally convert non-OOXML Word, Excel, PowerPoint and Rich Text File documents to OOXML. The script outputs DOT files that can be exported as images using Graphviz. If Graphviz is in your PATH you can also export to an SVG (preferred) or PNG image.

## Application

You can find regular posts with results of using this script at [https://github.com/jstrosch/malware-samples](https://github.com/jstrosch/malware-samples)

 ## Output 
 Example image hash similarity graph (cropped). Here each node is a unique image that is connected by edges to other images that met the similarity threshold:

 <img src="https://user-images.githubusercontent.com/1920756/103389929-6651e800-4ad7-11eb-9c67-cc24ca0642ad.png" width="700">
 
 Example CSV output of the script in detect mode, which lists images that match the similarity threshold with the signatures in the blacklist file,[image_hash_signatures.txt](https://github.com/cryptogramfan/Malware-Analysis-Scripts/blob/master/graph_similar_document_images/image_hash_signatures.txt):
 
 <img src="https://raw.githubusercontent.com/cryptogramfan/Malware-Analysis-Scripts/master/graph_similar_document_images/images/graph_similar_document_images_screenshot_2.png" width="700">

### Abuse.ch Integration for Malware Signatures
 The script also queries the [Abuse.ch](https://abuse.ch) [API](https://urlhaus-api.abuse.ch/) to retrieve the malware signature of each sample, if available. Currently, this information is added as a label to the graph (although hard to see) as well as textual output upon script completion.

 <img src="https://user-images.githubusercontent.com/1920756/103390472-39530480-4ada-11eb-9c42-5165a3b30980.png" width="700">

 For the look-up to work, the input files must be named with their MD5 hash (no extension). If you would like to use a different hashing algorithm, ensure that you update the parameters for the Abuse.ch API.
 
 ## Example usage
 Convert documents to OOXML, extract images from the documents, identify images that are similar to the blacklist and then graph images that meet the similarity threshold: 
 ```
 $ graph_similar_document_images.py -f ~/Samples -d image_hash_signatures.txt -c -g -t 80 -o svg
 ```
 ## Help
 ```
usage: graph_similar_document_images.py [-h] -f INPUT_DIR
                                        [-t MIN_SIMILARITY_THRESHOLD]
                                        [-d SIG_FILE] [-g] [-c] [-o {svg,png}]

Usage: graph_similar_document_images.py -f <directory_containing_documents> -c -d <image_hash_signatures.txt>
-g -t <min_similarity_threshold> -o <svg|png>

optional arguments:
  -h, --help            show this help message and exit
  -f INPUT_DIR, --files INPUT_DIR
                        Directory to process
  -t MIN_SIMILARITY_THRESHOLD, --threshold MIN_SIMILARITY_THRESHOLD
                        Minimum percentage similarity between images to graph
                        (0 to 100)
  -d SIG_FILE, --detect SIG_FILE
                        Detect mode identifies images that are similar to a
                        blacklist of known-bad images
  -g, --graph           Graph mode creates a graph of images that meet the
                        similarity threshold
  -c, --convert         Try converting documents to OOXML using LibreOffice
  -o {svg,png}, --output {svg,png}
                        Output image format
 ```
 ## Supported platforms
 Tested on Ubuntu 18.04 with Python 3.
 
 ## Installation
 First install Graphviz and LibreOffice:
 ``` 
 $ sudo add-apt-repository ppa:libreoffice/ppa
 $ sudo apt update
 $ sudo apt install graphviz libreoffice
 ```
 Afterwards, install the required Python libraries:
 ```
 $ python3 -m pip install -r requirements.txt
 ```
 To view SVG files produced by the script you can use a viewer such as [Inkscape](https://inkscape.org/). Outputting to PNG isn't recommended because the resulting files can be large.
 
 ## License
 Released under the Creative Commons Attribution 4.0 International ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)) license.