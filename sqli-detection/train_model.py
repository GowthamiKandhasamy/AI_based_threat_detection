import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from scipy.sparse import hstack

# Load the preprocessed dataset
df = pd.read_csv('Preprocessed_SQL_Dataset.csv')

# Handle missing values in the 'Query_cleaned' column
df['Query_cleaned'].fillna('', inplace=True)

# Feature Engineering: TF-IDF Vectorization
vectorizer = TfidfVectorizer(ngram_range=(1, 1), max_features=5000)
X_tfidf_sparse = vectorizer.fit_transform(df['Query_cleaned'])
query_lengths = df['Query_cleaned'].apply(len).values.reshape(-1, 1)

# Combine sparse TF-IDF features with the length-based feature
X_combined_sparse = hstack([X_tfidf_sparse, query_lengths])

# Target variable (labels)
y = df['Label']

# Split the data into training and testing sets (80% training, 20% testing)
X_train, X_test, y_train, y_test = train_test_split(X_combined_sparse, y, test_size=0.2, random_state=42)

# Initialize and train a RandomForestClassifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predictions on the test set
y_test_pred = model.predict(X_test)
test_accuracy = accuracy_score(y_test, y_test_pred)

# Predictions on the training set to calculate training accuracy
y_train_pred = model.predict(X_train)
train_accuracy = accuracy_score(y_train, y_train_pred)

# Print classification reports and accuracies
print("Test Set Classification Report:")
print(classification_report(y_test, y_test_pred))
print(f"Test Accuracy: {test_accuracy * 100:.2f}%")

print("Training Set Classification Report:")
print(classification_report(y_train, y_train_pred))
print(f"Training Accuracy: {train_accuracy * 100:.2f}%")

# Save the trained model and vectorizer as joblib files
joblib.dump(model, 'trained_sql_injection_model.joblib')
joblib.dump(vectorizer, 'tfidf_vectorizer.joblib')

print("Model and vectorizer saved successfully.")
