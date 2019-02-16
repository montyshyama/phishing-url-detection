from sklearn.externals import joblib
import feature_extraction

classifier = joblib.load('model/trained.pkl')

print ('[+]Enter URL:')
url = input()
check = feature_extraction.main(url)
prediction = classifier.predict(check)
print (prediction)
