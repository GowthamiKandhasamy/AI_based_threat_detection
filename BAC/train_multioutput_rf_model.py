import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
import joblib
import warnings
import gc  # Garbage collector for memory optimization

# Suppress warnings to reduce clutter
warnings.filterwarnings('ignore')

# Load datasets
train_data = pd.read_csv('./data/train_data_updated.csv')
validation_data = pd.read_csv('./data/validation_data_updated.csv')
test_data = pd.read_csv('./data/test_data_updated.csv')

# Define the feature columns (dropping the unnecessary ones)
features = [
    'method', 'status_code', 'response_size', 
    'user_role', 'resource_sensitivity', 'access_type', 
    'is_manipulated', 'is_id_match'
]

# Define the target columns
target = ['bac_vulnerability', 'severity_level', 'priority']

# Split data into features and targets
X_train = train_data[features]
y_train = train_data[target]
X_valid = validation_data[features]
y_valid = validation_data[target]
X_test = test_data[features]
y_test = test_data[target]

# Convert target columns to consistent string types
for col in target:
    y_train[col] = y_train[col].astype(str)
    y_valid[col] = y_valid[col].astype(str)
    y_test[col] = y_test[col].astype(str)

# Preprocessing and encoding
def preprocess_data(X, preprocessor=None):
    categorical_cols = ['method', 'user_role', 'resource_sensitivity', 'access_type', 'is_manipulated', 'is_id_match']
    numeric_cols = ['status_code', 'response_size']
    
    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
        ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False))  # Ensure dense output for memory
    ])
    
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_cols),
            ('cat', categorical_transformer, categorical_cols)
        ]
    )
    
    # Process and return preprocessed data and the preprocessor itself
    return preprocessor.fit_transform(X), preprocessor

# Preprocess the training data and save the preprocessor
print("Preprocessing training data...")
X_train_processed, preprocessor = preprocess_data(X_train)
joblib.dump(preprocessor, './models/multioutput_preprocessor.pkl')

# Apply preprocessing to validation and test data
print("Preprocessing validation and test data...")
X_valid_processed = preprocessor.transform(X_valid)
X_test_processed = preprocessor.transform(X_test)

# Clear memory
gc.collect()

# Define the RandomForest model with reduced complexity (can be adjusted)
rf_model = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1)  # Increase depth and trees gradually if needed

# Wrap the RandomForest in MultiOutputClassifier for multi-target prediction
multi_output_model = MultiOutputClassifier(rf_model)

# Train the model with the full dataset
print("Training the model...")
multi_output_model.fit(X_train_processed, y_train)

# Save the trained model
joblib.dump(multi_output_model, './models/multioutput_rf_model.pkl')

# Predict on validation and test data
print("Predicting on validation and test data...")
y_valid_pred = multi_output_model.predict(X_valid_processed)
y_test_pred = multi_output_model.predict(X_test_processed)

# Print evaluation metrics for each target
print("\nValidation Data Classification Reports:")
for i, col in enumerate(target):
    print(f"{col} Validation Data Classification Report:")
    print(classification_report(y_valid[col], y_valid_pred[:, i]))
    print(f"{col} Validation Data Accuracy Score:", accuracy_score(y_valid[col], y_valid_pred[:, i]))

print("\nTest Data Classification Reports:")
for i, col in enumerate(target):
    print(f"{col} Test Data Classification Report:")
    print(classification_report(y_test[col], y_test_pred[:, i]))
    print(f"{col} Test Data Accuracy Score:", accuracy_score(y_test[col], y_test_pred[:, i]))

# Clear memory after execution
gc.collect()
