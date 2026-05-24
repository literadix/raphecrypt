const RANDOM_LEN = 40;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let wasm;

const elements = {
  runtimeStatus: document.querySelector("#runtime-status"),
  tabs: [...document.querySelectorAll(".tab")],
  encodePanel: document.querySelector("#encode-panel"),
  decodePanel: document.querySelector("#decode-panel"),
  visibleText: document.querySelector("#visible-text"),
  hiddenText: document.querySelector("#hidden-text"),
  encodePassword: document.querySelector("#encode-password"),
  encodedOutput: document.querySelector("#encoded-output"),
  encodedInput: document.querySelector("#encoded-input"),
  decodePassword: document.querySelector("#decode-password"),
  decodedOutput: document.querySelector("#decoded-output"),
  encodeButton: document.querySelector("#encode-button"),
  decodeButton: document.querySelector("#decode-button"),
  copyEncoded: document.querySelector("#copy-encoded"),
  copyDecoded: document.querySelector("#copy-decoded"),
  encodeMessage: document.querySelector("#encode-message"),
  decodeMessage: document.querySelector("#decode-message"),
};

init();

async function init() {
  setBusy(true);

  try {
    wasm = await loadWasm();
    elements.runtimeStatus.textContent = "WASM ready";
    elements.runtimeStatus.className = "status ready";
  } catch (error) {
    elements.runtimeStatus.textContent = error.message;
    elements.runtimeStatus.className = "status error";
    return;
  } finally {
    setBusy(false);
  }

  bindUi();
}

async function loadWasm() {
  const imports = {};

  if (WebAssembly.instantiateStreaming) {
    try {
      const result = await WebAssembly.instantiateStreaming(
        fetch("./raphecrypt.wasm"),
        imports,
      );
      return result.instance.exports;
    } catch (_error) {
      // Some static servers do not send `application/wasm`.
    }
  }

  const response = await fetch("./raphecrypt.wasm");

  if (!response.ok) {
    throw new Error("WASM file not found");
  }

  const bytes = await response.arrayBuffer();
  const result = await WebAssembly.instantiate(bytes, imports);

  return result.instance.exports;
}

function bindUi() {
  elements.tabs.forEach((tab) => {
    tab.addEventListener("click", () => selectMode(tab.dataset.mode));
  });

  elements.encodeButton.addEventListener("click", encodeText);
  elements.decodeButton.addEventListener("click", decodeText);
  elements.copyEncoded.addEventListener("click", () =>
    copyText(elements.encodedOutput.value, elements.encodeMessage),
  );
  elements.copyDecoded.addEventListener("click", () =>
    copyText(elements.decodedOutput.value, elements.decodeMessage),
  );
}

function selectMode(mode) {
  elements.tabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.mode === mode);
  });

  elements.encodePanel.classList.toggle("active", mode === "encode");
  elements.decodePanel.classList.toggle("active", mode === "decode");
}

function encodeText() {
  clearMessage(elements.encodeMessage);

  try {
    const password = elements.encodePassword.value;
    const random = password ? cryptoRandomBytes(RANDOM_LEN) : new Uint8Array();
    const output = callWasmString(
      wasm.raphecrypt_encode,
      elements.visibleText.value,
      elements.hiddenText.value,
      password,
      random,
    );

    elements.encodedOutput.value = output;
    elements.encodedInput.value = output;
    showMessage(elements.encodeMessage, "Encoded", "ok");
  } catch (error) {
    showMessage(elements.encodeMessage, error.message, "error");
  }
}

function decodeText() {
  clearMessage(elements.decodeMessage);

  try {
    const output = callWasmString(
      wasm.raphecrypt_decode,
      elements.encodedInput.value,
      elements.decodePassword.value,
    );

    elements.decodedOutput.value = output;
    showMessage(elements.decodeMessage, "Decoded", "ok");
  } catch (_error) {
    elements.decodedOutput.value = "";
    showMessage(elements.decodeMessage, "Decode failed", "error");
  }
}

function callWasmString(fn, ...values) {
  const allocations = values.map((value) =>
    value instanceof Uint8Array ? allocBytes(value) : allocText(value),
  );

  try {
    const args = allocations.flatMap((allocation) => [
      allocation.ptr,
      allocation.len,
    ]);
    const packed = fn(...args);

    if (packed === 0n) {
      throw new Error(takeLastError());
    }

    return takeResult(packed);
  } finally {
    allocations.forEach((allocation) => {
      if (allocation.ptr !== 0 && allocation.len > 0) {
        wasm.raphecrypt_dealloc(allocation.ptr, allocation.len);
      }
    });
  }
}

function allocText(value) {
  return allocBytes(encoder.encode(value));
}

function allocBytes(bytes) {
  if (bytes.length === 0) {
    return { ptr: 0, len: 0 };
  }

  const ptr = wasm.raphecrypt_alloc(bytes.length);
  new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);

  return { ptr, len: bytes.length };
}

function takeResult(packed) {
  const { ptr, len } = unpackPtrLen(packed);

  if (len === 0) {
    return "";
  }

  const bytes = new Uint8Array(wasm.memory.buffer, ptr, len);
  const value = decoder.decode(bytes);
  wasm.raphecrypt_free_result(ptr, len);

  return value;
}

function takeLastError() {
  const packed = wasm.raphecrypt_last_error();
  return takeResult(packed);
}

function unpackPtrLen(packed) {
  return {
    ptr: Number(packed >> 32n),
    len: Number(packed & 0xffff_ffffn),
  };
}

function cryptoRandomBytes(len) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function copyText(value, messageElement) {
  clearMessage(messageElement);

  try {
    await navigator.clipboard.writeText(value);
    showMessage(messageElement, "Copied", "ok");
  } catch (_error) {
    showMessage(messageElement, "Copy failed", "error");
  }
}

function clearMessage(element) {
  element.textContent = "";
  element.className = "message";
}

function showMessage(element, message, kind) {
  element.textContent = message;
  element.className = `message ${kind}`;
}

function setBusy(isBusy) {
  [
    elements.encodeButton,
    elements.decodeButton,
    elements.copyEncoded,
    elements.copyDecoded,
  ].forEach((button) => {
    button.disabled = isBusy;
  });
}
