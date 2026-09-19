const delay = ms => new Promise(res => setTimeout(res, ms));
let scrambleInterval;
const chars = '0123456789ABCDEF!@#$%^&*';

function startScramble() {
    const display = document.getElementById('hash-display');
    if (!display) return;
    display.classList.remove('hidden-element');
    display.style.color = '#d63384';
    scrambleInterval = setInterval(() => {
        let text = '';
        for (let i = 0; i < 16; i++) text += chars.charAt(Math.floor(Math.random() * chars.length));
        display.innerText = "0x" + text + "...";
    }, 50);
}

function stopScramble() {
    clearInterval(scrambleInterval);
    const display = document.getElementById('hash-display');
    if (!display) return;
    display.innerText = "0x1f51cef21a6bd8010587d...";
    display.style.color = "#198754";
    setTimeout(() => { display.classList.add('hidden-element'); }, 400);
}

function animateProgress(stepNum, durationMs, colorClass = 'bg-primary') {
    return new Promise(resolve => {
        const bar = document.getElementById(`pbar${stepNum}`);
        const text = document.getElementById(`ptext${stepNum}`);
        if (!bar || !text) {
            setTimeout(resolve, durationMs);
            return;
        }

        const interval = 25;
        const totalSteps = durationMs / interval;
        let currentStep = 0;

        const timer = setInterval(() => {
            currentStep++;
            const pct = Math.min(Math.round((currentStep / totalSteps) * 100), 100);
            bar.style.width = `${pct}%`;
            text.innerText = `${pct}%`;

            if (currentStep >= totalSteps) {
                clearInterval(timer);
                bar.classList.remove('bg-primary', 'bg-warning');
                bar.classList.add('bg-success');
                text.classList.add('text-success', 'fw-bold');
                resolve();
            }
        }, interval);
    });
}

/**
 * Synchronized Wizard Animation:
 * Steps run smoothly and dynamically hold at Step 4 until scanPromise resolves.
 */
async function playWizardAnimation(wantsEVM = true, provider = 'azure', scanPromise = null) {
    const activeProvider = (provider || 'azure').toLowerCase();
    const isAws = activeProvider === 'aws';
    const activeColorClass = isAws ? 'bg-warning' : 'bg-primary';
    const activeStepClass = isAws ? 'active-step-aws' : 'active-step-azure';

    // 1. Set dynamic labels and icons
    const step1Text = document.getElementById('step-text-1');
    const step2Text = document.getElementById('step-text-2');
    const iconAzure = document.getElementById('icon1-azure');
    const iconAws = document.getElementById('icon1-aws');
    const wizardTitleText = document.getElementById('wizard-title-text');

    if (step1Text) {
        step1Text.innerText = isAws ? '1. Initializing AWS Boto3 SDK Session...' : '1. Connecting to Azure Resource Manager (ARM)...';
    }
    if (step2Text) {
        step2Text.innerText = isAws ? '2. Evaluating NIST CSF & CIS AWS Foundations...' : '2. Evaluating NIST CSF & CIS Azure Benchmark...';
    }
    if (wizardTitleText) {
        wizardTitleText.innerText = isAws ? 'Auditing AWS Cloud Environment...' : 'Auditing Azure Cloud Environment...';
    }

    // 2. Reset UI
    [1, 2, 3, 4].forEach(i => {
        const row = document.getElementById(`step${i}`);
        if (row) row.className = 'step-row';
        const done = document.getElementById(`done${i}`);
        if (done) done.classList.add('hidden-element');
        const icon = document.getElementById(`icon${i}`);
        if (icon) icon.classList.add('hidden-element');
        const bar = document.getElementById(`pbar${i}`);
        if (bar) {
            bar.style.width = '0%';
            bar.className = `progress-bar ${activeColorClass}`;
        }
        const ptext = document.getElementById(`ptext${i}`);
        if (ptext) {
            ptext.innerText = '0%';
            ptext.className = 'small text-muted font-monospace';
        }
    });

    if (iconAzure) iconAzure.classList.toggle('hidden-element', isAws);
    if (iconAws) iconAws.classList.toggle('hidden-element', !isAws);

    const step4Text = document.getElementById('step-text-4');
    if (step4Text) step4Text.innerHTML = '4. Appending to Ganache Blockchain...';

    const hashDisp = document.getElementById('hash-display');
    if (hashDisp) hashDisp.classList.add('hidden-element');
    const finalStep = document.getElementById('final-step');
    if (finalStep) finalStep.classList.add('hidden-element');

    // STEP 1: API Connection
    const row1 = document.getElementById('step1');
    row1.classList.add(activeStepClass);
    await animateProgress(1, 1000, activeColorClass);
    row1.classList.remove(activeStepClass);
    row1.classList.add('done-step');
    if (iconAzure) iconAzure.classList.add('hidden-element');
    if (iconAws) iconAws.classList.add('hidden-element');
    document.getElementById('done1').classList.remove('hidden-element');

    // STEP 2: Compliance Rules Engine
    const row2 = document.getElementById('step2');
    row2.classList.add(activeStepClass);
    document.getElementById('icon2').classList.remove('hidden-element');
    await animateProgress(2, 1100, activeColorClass);
    row2.classList.remove(activeStepClass);
    row2.classList.add('done-step');
    document.getElementById('icon2').classList.add('hidden-element');
    document.getElementById('done2').classList.remove('hidden-element');

    // STEP 3: Cryptographic State Hashing
    const row3 = document.getElementById('step3');
    row3.classList.add(activeStepClass);
    document.getElementById('icon3').classList.remove('hidden-element');
    startScramble();
    await animateProgress(3, 1100, activeColorClass);
    stopScramble();
    row3.classList.remove(activeStepClass);
    row3.classList.add('done-step');
    document.getElementById('icon3').classList.add('hidden-element');
    document.getElementById('done3').classList.remove('hidden-element');

    // STEP 4: EVM Blockchain Anchor & Backend Await
    const row4 = document.getElementById('step4');
    const pbar4 = document.getElementById('pbar4');
    const ptext4 = document.getElementById('ptext4');

    if (wantsEVM) {
        row4.classList.add(activeStepClass);
        document.getElementById('icon4').classList.remove('hidden-element');
        await animateProgress(4, 1000, activeColorClass);

        // If backend scan is still working, hold gracefully on Step 4
        if (scanPromise) {
            if (wizardTitleText) wizardTitleText.innerText = 'Finalizing cryptographic ledger & report...';
            await scanPromise;
        }

        row4.classList.remove(activeStepClass);
        row4.classList.add('done-step');
        document.getElementById('icon4').classList.add('hidden-element');
        document.getElementById('done4').classList.remove('hidden-element');
    } else {
        row4.classList.add('text-muted');
        if (step4Text) {
            step4Text.innerHTML = '4. Appending to Ganache Blockchain... <span class="badge bg-secondary ms-2" style="font-size: 10px;">Skipped (Off-Chain)</span>';
        }
        if (pbar4) {
            pbar4.style.width = '100%';
            pbar4.className = 'progress-bar bg-secondary';
        }
        if (ptext4) {
            ptext4.innerText = 'OFF';
            ptext4.className = 'small text-secondary font-monospace fw-bold';
        }
        if (scanPromise) await scanPromise;
    }

    // Success checkmark bounce
    const finalStepHeading = document.getElementById('final-step-heading');
    if (finalStepHeading) {
        finalStepHeading.innerText = isAws ? 'AWS Audit Complete!' : 'Azure Audit Complete!';
    }
    if (finalStep) finalStep.classList.remove('hidden-element');

    await delay(500);
}