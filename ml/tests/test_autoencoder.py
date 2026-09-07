import pytest
from ml.models.autoencoder import FlowAutoencoder
import torch


def test_autoencoder_forward_pass():
    model = FlowAutoencoder(input_dim=12)
    x = torch.randn(4, 12)
    output = model(x)
    assert output.shape == (4, 12)


def test_autoencoder_encode():
    model = FlowAutoencoder(input_dim=12)
    x = torch.randn(8, 12)
    encoded = model.encode(x)
    assert encoded.shape == (8, 4)


def test_autoencoder_reconstruct():
    model = FlowAutoencoder(input_dim=12)
    x = torch.randn(2, 12)
    reconstructed = model.reconstruct(x)
    assert reconstructed.shape == (2, 12)


def test_autoencoder_deterministic():
    model = FlowAutoencoder(input_dim=12)
    model.eval()
    x = torch.randn(1, 12)
    with torch.no_grad():
        out1 = model(x)
        out2 = model(x)
    assert torch.allclose(out1, out2)


def test_autoencoder_different_input_dim():
    model = FlowAutoencoder(input_dim=6)
    x = torch.randn(3, 6)
    output = model(x)
    assert output.shape == (3, 6)


def test_autoencoder_encoding_dim():
    model = FlowAutoencoder(input_dim=12, encoding_dim=2)
    x = torch.randn(5, 12)
    encoded = model.encode(x)
    assert encoded.shape == (5, 2)
