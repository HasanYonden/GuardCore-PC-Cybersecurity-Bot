const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const isDev = process.env.NODE_ENV === 'development';

// Python backend process management
const { spawn } = require('child_process');
let pyProc = null;
let mainWindow = null;

// Start the Python backend process
function startPythonProcess() {
  const pythonPath = isDev 
    ? path.join(__dirname, '..', '..', 'venv', 'Scripts', 'python.exe') 
    : path.join(process.resourcesPath, 'backend', 'venv', 'Scripts', 'python.exe');
  
  const scriptPath = isDev
    ? path.join(__dirname, '..', '..', 'ui', 'api', 'server.py')
    : path.join(process.resourcesPath, 'backend', 'server.py');

  if (fs.existsSync(scriptPath)) {
    pyProc = spawn(pythonPath, [scriptPath]);
    
    pyProc.stdout.on('data', (data) => {
      console.log(`Python stdout: ${data}`);
      // When backend is ready - this is a simplistic approach
      if (data.toString().includes('Server started')) {
        setTimeout(() => {
          if (mainWindow) {
            mainWindow.webContents.send('backend-ready');
          }
        }, 500);
      }
    });
    
    pyProc.stderr.on('data', (data) => {
      console.error(`Python stderr: ${data}`);
    });
    
    pyProc.on('close', (code) => {
      console.log(`Python process exited with code ${code}`);
      pyProc = null;
    });
  } else {
    console.error(`Python script not found: ${scriptPath}`);
    dialog.showErrorBox('Error', 'Could not find the backend server script.');
  }
}

// Create the Electron application window
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    show: false, // Don't show until loaded
    icon: path.join(__dirname, 'assets', 'icons', 'icon.png')
  });

  // Load the app
  const startUrl = isDev
    ? 'http://localhost:3000' // React dev server
    : `file://${path.join(__dirname, '../build/index.html')}`; // Production build
  
  mainWindow.loadURL(startUrl);

  // Show when ready to avoid white flashing
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    
    // In development mode, open DevTools automatically
    if (isDev) {
      mainWindow.webContents.openDevTools();
    }
  });

  // Window events
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// App lifecycle events
app.on('ready', () => {
  // Create the main window
  createWindow();
  
  // Start the Python process
  startPythonProcess();
});

app.on('window-all-closed', () => {
  // Quit the app on all platforms except macOS
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  // Re-create the window on macOS when the dock icon is clicked
  if (mainWindow === null) {
    createWindow();
  }
});

app.on('will-quit', () => {
  // Kill the Python process when the app is closing
  if (pyProc !== null) {
    pyProc.kill();
    pyProc = null;
  }
});

// IPC Event Handlers
ipcMain.handle('app-version', () => {
  return app.getVersion();
});

ipcMain.handle('show-open-dialog', async (event, options) => {
  const result = await dialog.showOpenDialog(options);
  return result;
});

ipcMain.handle('show-save-dialog', async (event, options) => {
  const result = await dialog.showSaveDialog(options);
  return result;
});

ipcMain.handle('show-message-box', async (event, options) => {
  const result = await dialog.showMessageBox(options);
  return result;
});