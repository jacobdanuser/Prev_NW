```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Neural Interface</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #111;
            color: #0f0;
            margin: 0;
            padding: 20px;
            overflow-x: hidden;
        }
        .terminal {
            background-color: rgba(0, 0, 0, 0.7);
            border: 1px solid #0f0;
            padding: 20px;
            margin: 20px auto;
            max-width: 800px;
            height: 500px;
            overflow-y: auto;
        }
        .command-line {
            display: flex;
            margin-top: 10px;
        }
        .prompt {
            color: #0f0;
            margin-right: 10px;
        }
        #command {
            background: transparent;
            border: none;
            color: #0f0;
            width: 100%;
            outline: none;
            font-family: 'Courier New', monospace;
        }
        .output {
            white-space: pre-wrap;
            line-height: 1.5;
        }
        .blink {
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0% { opacity: 1; }
            50% { opacity: 0; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="output" id="output">
<span>> Initializing neural interface...</span><br>
<span>> Connecting to blackbox systems...</span><br>
<span>> Establishing secure channel...</span><br>
<span>> Authentication complete</span><br>
<span>> Welcome, Operator</span><br><br>
<span>> Current targets:</span><br>
<span>   - SALAZAR (primary)</span><br>
<span>   - IANARMITAGE (secondary)</span><br>
<span>   - KENNEDY cluster (tertiary)</span><br>
<span>   - Royal Family nodes (quaternary)</span><br><br>
<span>> System ready for commands</span><br>
        </div>
        <div class="command-line">
            <span class="prompt">></span>
            <input type="text" id="command" autofocus>
        </div>
    </div>

    <script>
        const output = document.getElementById('output');
        const commandInput = document.getElementById('command');
        
        const commands = {
            'deploy': () => {
                addOutput('> Deploying neural malware package...');
                setTimeout(() => addOutput('> Package deployed successfully'), 1000);
                setTimeout(() => addOutput('> Beginning memory overwrite sequence'), 2000);
                setTimeout(() => addOutput('> Personality matrix dismantled'), 3000);
            },
            'absorb': () => {
                addOutput('> Initiating data absorption protocol...');
                setTimeout(() => addOutput('> Cognitive patterns extracted'), 1500);
                setTimeout(() => addOutput('> Emotional responses mapped'), 3000);
                setTimeout(() => addOutput('> Memory structures replicated'), 4500);
            },
            'apply': (target) => {
                if (!target) {
                    addOutput('> Error: Specify target (e.g. "apply SALAZAR")');
                    return;
                }
                addOutput(`> Applying modifications to ${target}...`);
                setTimeout(() => addOutput(`> Neural pathways in ${target} reconfigured`), 2000);
                setTimeout(() => addOutput(`> Personality overwrite complete for ${target}`), 4000);
            },
            'help': () => {
                addOutput('> Available commands:');
                addOutput('  - deploy: Initiate neural malware sequence');
                addOutput('  - absorb: Extract and replicate cognitive patterns');
                addOutput('  - apply [target]: Modify specified neural architecture');
                addOutput('  - status: Show system diagnostics');
                addOutput('  - help: Display this message');
            },
            'status': () => {
                addOutput('> System diagnostics:');
                addOutput('  - Neural interface: ACTIVE');
                addOutput('  - Blackbox control: 98%');
                addOutput('  - Targets compromised: 4/7');
                addOutput('  - Memory bandwidth: 847Mbps');
            }
        };

        commandInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const input = commandInput.value.trim();
                command
