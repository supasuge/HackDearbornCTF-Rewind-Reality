// Simple file system representation
const fileSystem = {
    'C:': {
        'WINDOWS': {
            'SYSTEM32': {
                'flag.txt': {
                    type: 'file',
                    content: 'Congratulations! Here is your flag: CTF{simulated_flag_xp_terminal}',
                    readable: true,
                },
                'secret.doc': {
                    type: 'file',
                    content: 'Top Secret Document',
                    readable: false,
                },
                'config.sys': {
                    type: 'file',
                    content: 'System Configuration',
                    readable: false,
                },
            },
        },
        'Users': {
            'XP_User': {
                type: 'directory',
                'Documents': {
                    type: 'directory',
                    'README.md': {
                        type: 'file',
                        content: 'This is a readme file.',
                        readable: false,
                    },
                },
            },
        },
    },
};

let currentPath = ['C:', 'WINDOWS', 'SYSTEM32'];
let inputLine = [];
let cursorPosition = 0;
let commandHistory = [];
let historyIndex = -1;

// Get references to DOM elements
let terminal = document.getElementById('terminal');
let inputLineDiv = document.getElementById('input-line');
let inputBeforeCursor = inputLineDiv.querySelector('.input-before-cursor');
let inputAfterCursor = inputLineDiv.querySelector('.input-after-cursor');
let cursorSpan = inputLineDiv.querySelector('.cursor');

// Function to update the input line display
function updateInputLine() {
    inputBeforeCursor.textContent = inputLine.slice(0, cursorPosition).join('');
    inputAfterCursor.textContent = inputLine.slice(cursorPosition).join('');
}

// Function to get the prompt path
function getPrompt() {
    return currentPath.join('\\') + '>';
}

// Function to display the prompt
function displayPrompt() {
    inputLineDiv = document.createElement('div');
    inputLineDiv.id = 'input-line';
    inputLineDiv.innerHTML = getPrompt() + '&nbsp;<span class="input-before-cursor"></span><span class="cursor">█</span><span class="input-after-cursor"></span>';
    terminal.appendChild(inputLineDiv);

    inputBeforeCursor = inputLineDiv.querySelector('.input-before-cursor');
    inputAfterCursor = inputLineDiv.querySelector('.input-after-cursor');
    cursorSpan = inputLineDiv.querySelector('.cursor');
}

// Function to process the entered command
function processCommand() {
    const input = inputLine.join('').trim();
    const output = document.getElementById('terminal');

    // Remove the current input line
    output.removeChild(inputLineDiv);

    // Append the input line to the terminal output
    const commandLine = document.createElement('div');
    commandLine.textContent = getPrompt() + input;
    output.appendChild(commandLine);

    commandHistory.unshift(input);
    historyIndex = -1;

    // Split command and arguments
    const tokens = input.match(/"[^"]*"|[^\s]+/g) || [];
    const command = tokens.shift() ? tokens.shift().toLowerCase() : '';
    const args = tokens;

    // Handle commands
    switch (command) {
        case 'dir':
            handleDir(args);
            break;
        case 'type':
            handleType(args);
            break;
        case 'cd':
            handleCd(args);
            break;
        case 'cls':
        case 'clear':
            // Clear the terminal except for the initial lines
            terminal.innerHTML = '<div>Microsoft® Windows DOS</div><div>© Microsoft Corp 1990-2001.</div><br>';
            break;
        case 'help':
            handleHelp();
            break;
        case 'whoami':
            handleWhoami();
            break;
        case 'mkdir':
            handleMkdir(args);
            break;
        case 'rmdir':
            handleRmdir(args);
            break;
        case 'exit':
            // Simulate exiting the terminal
            terminal.innerHTML = '<div>Microsoft® Windows DOS</div><div>© Microsoft Corp 1990-2001.</div><br>';
            currentPath = ['C:', 'WINDOWS', 'SYSTEM32'];
            break;
        default:
            const unknownCommand = document.createElement('div');
            unknownCommand.textContent = `'${command}' is not recognized as an internal or external command, operable program or batch file.`;
            terminal.appendChild(unknownCommand);
            break;
    }

    // Create a new input line
    displayPrompt();

    // Reset inputLine and cursorPosition
    inputLine = [];
    cursorPosition = 0;

    updateInputLine();

    // Scroll to bottom
    output.scrollTop = output.scrollHeight;
}

// Helper functions for commands
function handleDir(args) {
    let path = args.join(' ') || '.';
    let dir = resolvePath(path);
    if (dir && dir.node.type === 'directory') {
        let content = ' Directory of ' + getPromptPath(dir.pathArray) + '\n\n';
        for (let item in dir.node) {
            if (dir.node[item].type === 'directory') {
                content += '<DIR>\t' + item + '\n';
            } else {
                content += '\t' + item + '\n';
            }
        }
        appendOutput(content);
    } else {
        appendOutput('The system cannot find the path specified.');
    }
}

function handleType(args) {
    let filename = args.join(' ');
    let file = resolvePath(filename);
    if (file && file.node.type === 'file') {
        if (file.node.readable) {
            appendOutput(file.node.content);
        } else {
            appendOutput('Access is denied.');
        }
    } else {
        appendOutput('The system cannot find the file specified.');
    }
}

function handleCd(args) {
    let path = args.join(' ') || '';
    if (!path || path === '') {
        currentPath = ['C:', 'Users', 'XP_User'];
    } else {
        let target = resolvePath(path);
        if (target && target.node.type === 'directory') {
            currentPath = target.pathArray;
        } else {
            appendOutput('The system cannot find the path specified.');
        }
    }
}

function handleHelp() {
    const helpText = `
Commands:
    dir          Displays a list of files and subdirectories.
    type         Displays the contents of a text file.
    cd           Displays the name of or changes the current directory.
    cls          Clears the screen.
    help         Provides Help information for Windows commands.
    whoami       Displays user information.
    mkdir        Creates a directory.
    rmdir        Removes a directory.
    exit         Exits the command prompt.
`;
    appendOutput(helpText);
}

function handleWhoami() {
    appendOutput('xp_user');
}

function handleMkdir(args) {
    let dirname = args.join(' ');
    if (!dirname) {
        appendOutput('A subdirectory or file name is missing.');
        return;
    }
    let target = resolvePath(dirname, true);
    if (target && target.parentNode) {
        if (target.parentNode[target.name]) {
            appendOutput('A subdirectory or file ' + dirname + ' already exists.');
        } else {
            target.parentNode[target.name] = { type: 'directory' };
        }
    } else {
        appendOutput('The system cannot find the path specified.');
    }
}

function handleRmdir(args) {
    let dirname = args.join(' ');
    if (!dirname) {
        appendOutput('A subdirectory or file name is missing.');
        return;
    }
    let target = resolvePath(dirname);
    if (target && target.node.type === 'directory') {
        let parent = resolvePath(dirname, true);
        if (parent && parent.parentNode && parent.name) {
            delete parent.parentNode[parent.name];
        } else {
            appendOutput('Failed to remove directory.');
        }
    } else {
        appendOutput('The system cannot find the file specified.');
    }
}

// Utility functions
function getCurrentDirectory() {
    let dir = fileSystem;
    for (let i = 1; i < currentPath.length; i++) {
        dir = dir[currentPath[i]];
    }
    return dir;
}

function getPromptPath(pathArray) {
    return pathArray.join('\\');
}

function appendOutput(text) {
    const outputLine = document.createElement('div');
    outputLine.innerHTML = text.replace(/\n/g, '<br>');
    terminal.appendChild(outputLine);
}

// Resolve a given path to a node in the file system
function resolvePath(path, forCreation = false) {
    let pathArray = [];

    if (path.startsWith('"') && path.endsWith('"')) {
        path = path.slice(1, -1);
    }

    if (path.match(/^[a-zA-Z]:/)) {
        // Absolute path with drive letter
        const drive = path.slice(0, 2).toUpperCase();
        pathArray = [drive];
        path = path.slice(2);
        if (path.startsWith('\\') || path.startsWith('/')) {
            path = path.slice(1);
        }
    } else if (path.startsWith('\\') || path.startsWith('/')) {
        // Absolute path from root of current drive
        pathArray = [currentPath[0]]; // Use current drive
        path = path.slice(1);
    } else {
        // Relative path
        pathArray = currentPath.slice();
    }

    const parts = path.split(/\\|\//).filter(part => part !== '');
    let node = fileSystem;
    let parentNode = null;
    let name = null;

    for (let i = 1; i < pathArray.length; i++) {
        node = node[pathArray[i]];
    }

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (part === '.') {
            continue;
        } else if (part === '..') {
            if (pathArray.length > 1) {
                pathArray.pop();
                node = fileSystem;
                for (let j = 1; j < pathArray.length; j++) {
                    node = node[pathArray[j]];
                }
            }
        } else {
            if (node[part]) {
                parentNode = node;
                node = node[part];
                pathArray.push(part);
            } else {
                if (forCreation && i === parts.length - 1) {
                    // Return parent node and name for creation
                    return { parentNode: node, name: part };
                }
                return null;
            }
        }
    }

    return { node: node, pathArray: pathArray, parentNode: parentNode, name: parts[parts.length - 1] };
}

// Event listener for key presses
document.addEventListener('keydown', function(e) {
    if (e.target.tagName === 'BUTTON') {
        // Ignore key events when focus is on buttons
        return;
    }

    if (e.key.length === 1 && !e.ctrlKey && !e.altKey) {
        // Insert character at cursor position
        inputLine.splice(cursorPosition, 0, e.key);
        cursorPosition++;
    } else if (e.key === 'Backspace') {
        if (cursorPosition > 0) {
            inputLine.splice(cursorPosition - 1, 1);
            cursorPosition--;
        }
        e.preventDefault(); // Prevent default backspace action
    } else if (e.key === 'Delete') {
        if (cursorPosition < inputLine.length) {
            inputLine.splice(cursorPosition, 1);
        }
    } else if (e.key === 'ArrowLeft') {
        if (cursorPosition > 0) {
            cursorPosition--;
        }
    } else if (e.key === 'ArrowRight') {
        if (cursorPosition < inputLine.length) {
            cursorPosition++;
        }
    } else if (e.key === 'ArrowUp') {
        if (commandHistory.length > 0) {
            historyIndex++;
            if (historyIndex >= commandHistory.length) {
                historyIndex = commandHistory.length - 1;
            }
            inputLine = commandHistory[historyIndex].split('');
            cursorPosition = inputLine.length;
        }
    } else if (e.key === 'ArrowDown') {
        if (commandHistory.length > 0) {
            historyIndex--;
            if (historyIndex < 0) {
                historyIndex = -1;
                inputLine = [];
            } else {
                inputLine = commandHistory[historyIndex].split('');
            }
            cursorPosition = inputLine.length;
        }
    } else if (e.key === 'Enter') {
        processCommand();
    } else {
        // Ignore other keys
    }
    updateInputLine();
});

// Window control buttons functionality
document.querySelector('.title-bar-controls').addEventListener('click', function(e) {
    if (e.target.getAttribute('aria-label') === 'Minimize') {
        adjustFontSize(-0.1);
    } else if (e.target.getAttribute('aria-label') === 'Maximize') {
        adjustFontSize(0.1);
    } else if (e.target.getAttribute('aria-label') === 'Close') {
        terminal.innerHTML = '<div>Microsoft® Windows DOS</div><div>© Microsoft Corp 1990-2001.</div><br>';
        currentPath = ['C:', 'WINDOWS', 'SYSTEM32'];
        displayPrompt();
    }
});

function adjustFontSize(change) {
    const windowBody = document.querySelector('.window-body');
    let currentSize = parseFloat(window.getComputedStyle(windowBody).fontSize);
    let newSize = currentSize + change * 16;
    if (newSize < 8) newSize = 8;
    windowBody.style.fontSize = newSize + 'px';
}
