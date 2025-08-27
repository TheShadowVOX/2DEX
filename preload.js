// preload.js
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  hasPin: () => ipcRenderer.invoke("has-pin"),
  setPin: (pin) => ipcRenderer.invoke("set-pin", pin),
  verifyPin: (pin) => ipcRenderer.invoke("verify-pin", pin),
  getAccounts: () => ipcRenderer.invoke("get-accounts"),
  addAccount: (acc) => ipcRenderer.invoke("add-account", acc),
  generateOTP: (secret, opts) => ipcRenderer.invoke("generate-otp", secret, opts),
  parseOtpAuth: (uri) => ipcRenderer.invoke("parse-otpauth", uri),
  quit: () => ipcRenderer.send("quit"),
  selfDestruct: () => ipcRenderer.invoke("selfDestruct"),
  confirmDestruct: (input) => ipcRenderer.invoke("confirmDestruct", input),
   surprise: () => ipcRenderer.invoke("surprise"),
  exportVault: (filePath) => ipcRenderer.invoke("exportVault", filePath),
  importVault: (filePath) => ipcRenderer.invoke("importVault", filePath),
  openUserData: () => ipcRenderer.invoke("open-user-data"),

});
