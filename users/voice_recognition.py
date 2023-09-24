import os
import numpy as np
import librosa
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout, Flatten, Conv1D, MaxPooling1D
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split
from django.views.decorators.csrf import csrf_exempt

# # --- FEATURE EXTRACTION AND MODEL DEFINITION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.join(BASE_DIR, 'voicesamples')
def extract_features(file_name):
    """Extract MFCCs from an audio file."""
    if not os.path.exists(file_name):
        raise ValueError(f"File {file_name} not found!")

    audio, sample_rate = librosa.load(file_name, res_type='kaiser_fast')
    if audio.size == 0:
        raise ValueError(f"Empty audio data for file {file_name}!")
    
    mfccs = librosa.feature.mfcc(y=audio, sr=sample_rate, n_mfcc=40)
    if mfccs.size == 0:
        raise ValueError(f"Failed to extract MFCCs for file {file_name}!")

    mfccs_scaled = np.mean(mfccs.T, axis=0)
    return mfccs_scaled
def create_model(input_shape, num_classes):
    """Define the CNN model."""
    model = Sequential()
    model.add(Conv1D(128, 5, padding='same', activation='relu', input_shape=input_shape))
    model.add(MaxPooling1D(2))
    model.add(Dropout(0.2))
    model.add(Conv1D(128, 5, activation='relu'))
    model.add(MaxPooling1D(2))
    model.add(Dropout(0.2))
    model.add(Flatten())
    model.add(Dense(128, activation='relu'))
    model.add(Dense(num_classes, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model
def train_voice_model():
    """Train the voice model using collected voice samples."""
    
    voice_samples_dir = MEDIA_DIR
    
    # Load all voice samples
    voice_files = [f'test{i}.wav' for i in range(1, 6)]
    users = ["test"]

    # Extract features for each voice sample
    voice_features = {}
    for user in users:
        user_features = []
        for phase in range(1, 6):
            file_path = os.path.join(voice_samples_dir, f"test{phase}.wav")
            user_features.append(extract_features(file_path))
        voice_features[user] = user_features

    # Prepare Data for Training
    X = []
    y = []

    for user, features in voice_features.items():
        for feature in features:
            X.append(feature)
            y.append(users.index(user))

    if not X or not y:
        raise ValueError("No voice features or labels found. Ensure the voice samples are valid.")
    
    X = np.array(X)
    y = to_categorical(np.array(y))

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    input_shape = (X_train.shape[1], 1)
    X_train = X_train[..., np.newaxis]
    X_val = X_val[..., np.newaxis]

    model = create_model(input_shape, len(users))
    model.fit(X_train, y_train, epochs=50, validation_data=(X_val, y_val), batch_size=32)

    model.save("voice_model.h5")

    return model, users

# --- PREDICTION FUNCTION ---

def predict_user_voice(model_path="voice_model.h5"):
    """Predict the user's identity using the reference voice."""
    
    ref_voice_dir = MEDIA_DIR
    model = load_model(model_path)

    ref_voice_path = os.path.join(ref_voice_dir, "1.wav")
    ref_voice_features = extract_features(ref_voice_path)

    predictions = model.predict(np.array([ref_voice_features]))
    predicted_index = np.argmax(predictions)

    _, users = train_voice_model()
    predicted_user = users[predicted_index]

    return f"The reference voice is most likely of user: {predicted_user}"

# --- DATA LOADING AND TRAINING ---

# def train_voice_model():
#     """Train the voice model using collected voice samples."""
    
#     voice_samples_dir = MEDIA_DIR
    
#     # Load all voice samples
#     voice_files = [f for f in os.listdir(voice_samples_dir) if f.endswith('.wav')]
#     users = list(set([f.split('_')[0] for f in voice_files]))

#     # Extract features for each voice sample
#     voice_features = {}
#     for user in users:
#         user_features = []
#         for phase in range(1, 6):
#             file_path = os.path.join(voice_samples_dir, f"test{phase}.wav")
#             user_features.append(extract_features(file_path))
#         voice_features[user] = user_features

#     # Prepare Data for Training
#     X = []
#     y = []

#     for user, features in voice_features.items():
#         for feature in features:
#             X.append(feature)
#             y.append(users.index(user))

#     if not X or not y:
#         raise ValueError("No voice features or labels found. Ensure the voice samples are valid.")
    
#     X = np.array(X)
#     y = to_categorical(np.array(y))

#     X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

#     input_shape = (X_train.shape[1], 1)
#     X_train = X_train[..., np.newaxis]
#     X_val = X_val[..., np.newaxis]

#     model = create_model(input_shape, len(users))
#     model.fit(X_train, y_train, epochs=50, validation_data=(X_val, y_val), batch_size=32)

#     model.save("voice_model.h5")

#     return model, users

# --- PREDICTION FUNCTION ---

# def predict_user_voice(model_path="voice_model.h5"):
#     """Predict the user's identity using the reference voice."""
    
#     ref_voice_dir = "reference_voice"
#     model = load_model(model_path)

#     ref_voice_path = os.path.join(ref_voice_dir, "1.wav")
#     ref_voice_features = extract_features(ref_voice_path)

#     predictions = model.predict(np.array([ref_voice_features]))
#     predicted_index = np.argmax(predictions)

#     _, users = train_voice_model()
#     predicted_user = users[predicted_index]

#     return f"The reference voice is most likely of user: {predicted_user}"

