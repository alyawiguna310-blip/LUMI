"""Lightweight MFCC feature extractor using only numpy."""
import numpy as np


def _mel_filterbank(sr: int, n_fft: int, n_mels: int = 26,
                    fmin: float = 20.0, fmax: float | None = None) -> np.ndarray:
    fmax = fmax if fmax else sr / 2.0

    def hz2mel(f):
        return 2595.0 * np.log10(1.0 + f / 700.0)

    def mel2hz(m):
        return 700.0 * (10.0 ** (m / 2595.0) - 1.0)

    mels = np.linspace(hz2mel(fmin), hz2mel(fmax), n_mels + 2)
    freqs = mel2hz(mels)
    bins = np.floor((n_fft + 1) * freqs / sr).astype(int)

    fb = np.zeros((n_mels, n_fft // 2 + 1))
    for i in range(n_mels):
        left, center, right = bins[i], bins[i + 1], bins[i + 2]
        for j in range(left, center):
            fb[i, j] = (j - left) / (center - left + 1e-9)
        for j in range(center, right):
            fb[i, j] = (right - j) / (right - center + 1e-9)
    return fb


def mfcc(audio: np.ndarray, sr: int = 16000, n_mfcc: int = 13,
         n_fft: int = 512, hop: int = 160, n_mels: int = 26) -> np.ndarray:
    """Return MFCCs shape (n_frames, n_mfcc)."""
    if len(audio) < n_fft:
        return np.zeros((1, n_mfcc), dtype=np.float32)

    a = np.asarray(audio, dtype=np.float32)
    emphasized = np.append(a[0], a[1:] - 0.97 * a[:-1])

    n_frames = 1 + (len(emphasized) - n_fft) // hop
    if n_frames <= 0:
        return np.zeros((1, n_mfcc), dtype=np.float32)

    idx = np.arange(n_fft)[None, :] + hop * np.arange(n_frames)[:, None]
    frames = emphasized[idx] * np.hamming(n_fft)[None, :]

    spectrum = np.abs(np.fft.rfft(frames, n_fft)) ** 2

    fb = _mel_filterbank(sr, n_fft, n_mels)
    mel_energy = spectrum @ fb.T
    mel_energy = np.maximum(mel_energy, 1e-10)
    log_mel = np.log(mel_energy)

    n = np.arange(n_mels)
    k = np.arange(n_mfcc).reshape(-1, 1)
    dct_matrix = np.cos(np.pi * k * (2 * n + 1) / (2 * n_mels))
    return (log_mel @ dct_matrix.T).astype(np.float32)


def extract_features(audio: np.ndarray, sr: int = 16000) -> np.ndarray:
    """
    Turn a ~1.2s audio clip into a fixed-length feature vector.
    Returns shape (27,): mean+std of 13 MFCCs + log energy.

    Amplitude is normalized FIRST (peak → 0.5) so loud training clips
    and quiet runtime clips produce comparable features.
    """
    a = np.asarray(audio, dtype=np.float32).flatten()

    if len(a) == 0:
        return np.zeros(27, dtype=np.float32)

    # --- KEY: normalize amplitude up front. ---
    # Peak-normalize to 0.5 so both the mp3 training clips and the live
    # runtime buffer land in the same energy range. Without this, MFCC
    # values differ hugely between training and runtime.
    peak = float(np.max(np.abs(a)))
    if peak > 0.001:
        target = 0.5
        gain = target / peak
        # Cap gain at 30x — above that we're just amplifying noise.
        gain = min(gain, 30.0)
        a = a * gain
        # Don't clip: if the clip was already loud, gain would be < 1 and we
        # scale it down. If quiet, gain > 1 and we scale up.
        a = np.clip(a, -1.0, 1.0).astype(np.float32)

    # Trim leading/trailing silence so the useful part dominates.
    win = max(1, int(0.02 * sr))
    rms = np.sqrt(np.convolve(a ** 2, np.ones(win) / win, mode="same"))
    thr = max(0.01, 0.15 * float(np.max(rms)))
    active = np.where(rms > thr)[0]
    if len(active) > int(0.15 * sr):
        a = a[active[0]:active[-1] + 1]

    # Pad / trim to exactly 1.2 s
    target_len = int(1.2 * sr)
    if len(a) < target_len:
        a = np.pad(a, (0, target_len - len(a)))
    else:
        start = (len(a) - target_len) // 2
        a = a[start:start + target_len]

    coeffs = mfcc(a, sr=sr, n_mfcc=13)
    mean = coeffs.mean(axis=0)
    std = coeffs.std(axis=0)
    energy = np.array([np.log(np.mean(a ** 2) + 1e-10)], dtype=np.float32)
    return np.concatenate([mean, std, energy]).astype(np.float32)