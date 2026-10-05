"""Test the custom-trained 'lumi' openWakeWord model."""
import time
import numpy as np
import sounddevice as sd
from openwakeword.model import Model

SR = 16000
DEVICE = 2
CHUNK = 1280
MODEL_PATH = r"D:\Lumi\models\lumi.onnx"

print(f"Loading {MODEL_PATH}...")
model = Model(wakeword_models=[MODEL_PATH], inference_framework="onnx")
print("Say 'Lumi' 4-5 times. (15 sec test)")
print("-" * 60)

try:
    with sd.RawInputStream(
        samplerate=SR, channels=1, dtype="int16",
        blocksize=CHUNK, device=DEVICE,
    ) as stream:
        t0 = time.time()
        while time.time() - t0 < 15:
            data, _ = stream.read(CHUNK)
            pcm = np.frombuffer(bytes(data), dtype=np.int16)
            scores = model.predict(pcm)
            for name, score in scores.items():
                if score > 0.2:
                    print(f"  {score:.3f}")
            if any(s > 0.5 for s in scores.values()):
                print("*** LUMI DETECTED ***")
except KeyboardInterrupt:
    print("\nStopped.")

print("-" * 60)
print("Scores above 0.5 = success.")