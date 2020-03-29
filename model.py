import argparse
import re
from urllib.parse import urlparse
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer


def parse_args():
	parser = argparse.ArgumentParser()

	parser.add_argument('--model', type=str, default='third', 
						help='Indicates which model to select, first one includes last part of netlocation like .com, .au etc, second one has best accuracy and the third one is best in regards to identifying the malicious url')
	args = parser.parse_args()
	return args

def netloc_extractor_with(x):
	if(x[:4] != 'http'):
		x = 'http://' + x
	parsed_x = urlparse(x)
	netloc = str(parsed_x.netloc)
	netloc = netloc.replace(' ', '')
	netloc = netloc.replace('.', ' ')
	return netloc

def netloc_extract_without(x):
	if(x[:4] != 'http'):
		x = 'http://' + x
	parsed_x = urlparse(x)
	netloc = str(parsed_x.netloc)
	netloc = netloc.replace(' ', '')
	netloc = netloc.replace('.', ' ')
	lst = netloc.split(' ')
	final = lst[0]
	for i in range(1, len(lst) - 1):
		final = final + ' ' + lst[i]
	return final

def path_extractor(x):
	if x[:4] != 'http':
		x = 'http://' + x
	parsed_x = urlparse(x)
	path = str(parsed_x.path)
	path = path.replace(' ', '')
	path = path.replace('/', ' ')
	return path

def preprocess_url(x):
	if args.model == 'first':
		netloc = netloc_extractor_with(x)
	else:
		netloc = netloc_extract_without(x)
	path = path_extractor(x)

	if path != '':
		final = netloc + ' ' + path
	else:
		final = netloc
	return final


def main():
	global args
	args = parse_args()
	print('Please enter the Url you want to check')
	url = input()
	url = preprocess_url(url)
	sc = StandardScaler()
	if args.model == 'first':
		vect = pickle.load(open('weights/best_acc_with_tfidf.sav', 'rb'))
		sc = pickle.load(open('weights/best_acc_with_sc.sav', 'rb'))
		model = pickle.load(open('weights/best_acc_wtih.sav', 'rb'))
	elif args.model == 'second':
		vect = pickle.load(open('weights/best_acc_bow.sav', 'rb'))
		model = pickle.load(open('weights/best_acc.sav', 'rb'))
	else:
		vect = pickle.load(open('weights/best_bad_tfidf.sav', 'rb'))
		sc = pickle.load(open('weights/best_bad_sc.sav', 'rb'))
		model = pickle.load(open('weights/best_bad.sav', 'rb'))

	vec = vect.transform([url])
	if args.model != 'second':
		vec = sc.transform(vec)
	print(model.predict(vec))

if __name__ == '__main__':
	main()
