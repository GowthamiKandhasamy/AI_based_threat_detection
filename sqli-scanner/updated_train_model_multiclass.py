import os
import pandas as pd
import numpy as np
import re
import pickle  # Import pickle for saving the vectorizer
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.callbacks import EarlyStopping
from sklearn.metrics import classification_report, confusion_matrix

# Function for preprocessing SQL queries
def preprocess_data(data):
    data['Query'] = data['Query'].str.strip().str.lower()  # Normalize case and strip whitespace
    data['Query'] = data['Query'].apply(lambda x: re.sub(r'--.*|/\*.*?\*/', '', x))  # Remove comments
    return data

# Function for feature engineering using TF-IDF
def feature_engineering(data):
    vectorizer = TfidfVectorizer(max_features=5000)  # Limit to top 5000 features
    X = vectorizer.fit_transform(data['Query']).toarray()
    y = data['Label']
    return X, y, vectorizer

# Function to create the model
def create_model(input_dim, num_classes):
    model = Sequential()
    model.add(Dense(128, activation='relu', input_dim=input_dim))
    model.add(Dropout(0.5))
    model.add(Dense(64, activation='relu'))
    model.add(Dropout(0.5))
    model.add(Dense(num_classes, activation='softmax'))  # Multiclass classification
    model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model

# Function to evaluate the model
def evaluate_model(model, X_test, y_test):
    y_pred = np.argmax(model.predict(X_test), axis=1)  # Multiclass prediction
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    return y_pred

# Main function to load data, train, and evaluate the model
def train_and_evaluate_model(file_path):
    # Load and preprocess data
    data = pd.read_csv(file_path)
    data = preprocess_data(data)

    # Feature engineering
    X, y, vectorizer = feature_engineering(data)

    # Create models directory if it doesn't exist
    if not os.path.exists('models'):
        os.makedirs('models')

    # Save the vectorizer
    vectorizer_path = 'models/vectorizer.pkl'  # Specify the path to save the vectorizer
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    print(f'Vectorizer saved to {vectorizer_path}')

    # Stratified K-Fold cross-validation
    skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    for fold, (train_index, test_index) in enumerate(skf.split(X, y)):
        X_train, X_test = X[train_index], X[test_index]
        y_train, y_test = y[train_index], y[test_index]

        # Create and train the model
        model = create_model(X_train.shape[1], len(np.unique(y)))
        early_stopping = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)

        model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2, 
                  callbacks=[early_stopping], verbose=1)

        # Evaluate the model
        evaluate_model(model, X_test, y_test)

        # Save the model after each fold
        model_save_path = f'models/model_fold_{fold + 1}.h5'  # Save model as .h5 file in models directory
        model.save(model_save_path)
        print(f'Model saved to {model_save_path}')

if __name__ == "__main__":
    train_and_evaluate_model('SQL_Dataset_with_Vulnerability_Types.csv')
