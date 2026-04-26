import React, { useEffect, useMemo, useState } from 'react';
import type { KeyPair } from '../types';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { CheckIcon, CopyIcon, ExclamationTriangleIcon, CheckCircleIcon, DownloadIcon } from './icons/Icons';
import {
  analyzePublicKeyCompatibility,
  decryptPrivateKey,
  inspectCert,
  type CertInspection,
} from '../services/cryptoService';

interface Props {
  keyPair: KeyPair;
  onClose: () => void;
}

const KeyBlock: React.FC<{ title: string; content: string; filename: string }> = ({ title, content, filename }) => {
  const [isCopied, copy] = useCopyToClipboard();

  const handleDownload = () => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain;charset=utf-8' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div>
      <h3 className="text-lg font-medium text-gray-800 mb-2">{title}</h3>
      <div className="relative">
        <textarea
          readOnly
          value={content}
          rows={8}
          className="w-full p-3 bg-gray-100 border border-gray-300 rounded-md font-mono text-xs text-gray-700 focus:outline-none"
        />
        <div className="absolute top-2 right-2 flex space-x-2">
            <button
                onClick={handleDownload}
                className="flex items-center px-3 py-1.5 text-sm font-medium rounded-md bg-gray-200 hover:bg-gray-300 text-gray-700 transition"
                aria-label="Download as .asc file"
            >
                <DownloadIcon />
                <span className="ml-2">Download</span>
            </button>
            <button
              onClick={() => copy(content)}
              className="flex items-center px-3 py-1.5 text-sm font-medium rounded-md bg-gray-200 hover:bg-gray-300 text-gray-700 transition"
              aria-label={isCopied ? 'Copied to clipboard' : 'Copy to clipboard'}
            >
                <div className="flex items-center">
                  {isCopied ? <CheckIcon /> : <CopyIcon />}
                  <span className="ml-2">{isCopied ? 'Copied!' : 'Copy'}</span>
                </div>
            </button>
        </div>
      </div>
    </div>
  );
};

/**
 * Locked private-key panel. Asks for the passphrase, decrypts the envelope,
 * and reveals the plaintext TSK with Copy and Download buttons. The plaintext
 * is held only in component state — closing the modal drops it.
 */
const PrivateKeyPanel: React.FC<{ keyPair: KeyPair }> = ({ keyPair }) => {
  const isProtected = !!keyPair.salt;
  const [passphrase, setPassphrase] = useState('');
  const [revealedTsk, setRevealedTsk] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  // For unprotected keys, the plaintext TSK is already on the keyPair.
  const plaintextWhenUnprotected = keyPair.privateKeyPgp || keyPair.privateKeyRaw;

  const handleReveal = async () => {
    setError(null);
    setWorking(true);
    try {
      const tsk = await decryptPrivateKey(keyPair, passphrase);
      setRevealedTsk(tsk);
      setPassphrase(''); // wipe the passphrase from React state once we've used it
    } catch (e) {
      setError('Decryption failed. Wrong passphrase?');
    } finally {
      setWorking(false);
    }
  };

  const handleHide = () => {
    setRevealedTsk(null);
    setError(null);
  };

  const filename = `private-key-${keyPair.fingerprint.replace(/\s/g, '').slice(-16)}.asc`;

  // Unprotected key: just render the plaintext block straight away.
  if (!isProtected) {
    return <KeyBlock title="Private Key" content={plaintextWhenUnprotected} filename={filename} />;
  }

  // Protected key, not yet revealed: show passphrase prompt.
  if (!revealedTsk) {
    return (
      <div>
        <h3 className="text-lg font-medium text-gray-800 mb-2">Private Key</h3>
        <div className="p-4 rounded-md bg-gray-50 border border-gray-200 space-y-3">
          <p className="text-sm text-gray-700">
            This private key is protected by a passphrase. Enter it below to reveal the
            ASCII-armored secret key. The revealed key can be imported into <code className="bg-gray-200 px-1 rounded">sq</code> with{' '}
            <code className="bg-gray-200 px-1 rounded">sq key import</code>.
          </p>
          <div className="flex gap-2">
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && passphrase && !working) handleReveal(); }}
              placeholder="Enter passphrase"
              className="flex-1 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
              autoComplete="off"
            />
            <button
              onClick={handleReveal}
              disabled={working || !passphrase}
              className="px-4 py-2 text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition"
            >
              {working ? 'Decrypting…' : 'Reveal Private Key'}
            </button>
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>
      </div>
    );
  }

  // Revealed: show the plaintext TSK with Copy + Download, plus a Hide button.
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-medium text-gray-800">Private Key (revealed)</h3>
        <button
          onClick={handleHide}
          className="px-3 py-1 text-xs font-medium rounded-md bg-gray-200 hover:bg-gray-300 text-gray-700 transition"
        >
          Hide
        </button>
      </div>
      <KeyBlock title="" content={revealedTsk} filename={filename} />
      <p className="text-xs text-gray-500 mt-2">
        Tip: <code className="bg-gray-100 px-1 rounded">sq key import &lt; private-key-…asc</code> to add this to your local Sequoia keystore.
      </p>
    </div>
  );
};

/**
 * Structural inspector — shows what's actually inside the OpenPGP cert.
 * Like `sq inspect` but in the browser.
 */
const PacketInspector: React.FC<{ inspection: CertInspection | null; loading: boolean; error: string | null }> = ({ inspection, loading, error }) => {
  if (loading) {
    return (
      <div className="p-4 rounded-md bg-gray-50 border border-gray-200 text-gray-600 text-sm">
        Parsing cert structure…
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-4 rounded-md bg-red-50 border-l-4 border-red-400 text-red-800 text-sm">
        <p className="font-bold">Inspector error</p>
        <p>{error}</p>
      </div>
    );
  }
  if (!inspection) return null;

  return (
    <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
      <div className="bg-gray-50 px-4 py-3 border-b border-gray-200 flex items-center justify-between">
        <h3 className="text-lg font-medium text-gray-800">Packet Structure</h3>
        <span className="text-xs font-mono text-gray-500">sq inspect · in-browser</span>
      </div>

      <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
        <p className="text-xs uppercase tracking-wide text-gray-500 mb-1">Primary Key Packet (v{inspection.primary_key.version})</p>
        <p className="font-mono text-sm text-gray-900">{inspection.primary_key.algorithm}</p>
        <p className="font-mono text-xs text-gray-500 mt-1">Fingerprint: {inspection.fingerprint}</p>
        <p className="font-mono text-xs text-gray-500">Key ID: {inspection.keyid}</p>
        <p className="text-xs text-gray-500 mt-1">Created: {inspection.primary_key.creation_time}</p>
      </div>

      <div className="px-4 py-3 border-b border-gray-200">
        <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">User IDs ({inspection.user_ids.length})</p>
        {inspection.user_ids.length === 0 ? (
          <p className="text-sm text-gray-400 italic">No user IDs</p>
        ) : (
          <ul className="space-y-1">
            {inspection.user_ids.map((uid, i) => (
              <li key={i} className="flex items-center justify-between text-sm">
                <span className="font-mono text-gray-800">{uid.value}</span>
                <span className="flex items-center gap-2">
                  <span className="text-xs text-gray-500">{uid.self_signatures} self-sig{uid.self_signatures === 1 ? '' : 's'}</span>
                  {uid.revoked && <span className="text-xs text-red-600 font-semibold">revoked</span>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="px-4 py-3">
        <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Subkeys ({inspection.subkeys.length})</p>
        {inspection.subkeys.length === 0 ? (
          <p className="text-sm text-gray-400 italic">No subkeys</p>
        ) : (
          <ul className="space-y-3">
            {inspection.subkeys.map((sk, i) => (
              <li key={i} className="p-2 rounded bg-gray-50 border border-gray-200">
                <p className="font-mono text-sm text-gray-900">{sk.algorithm}</p>
                <p className="font-mono text-xs text-gray-500 break-all">{sk.fingerprint}</p>
                <p className="text-xs text-gray-500 mt-1">Created: {sk.creation_time}</p>
                <div className="mt-1 flex flex-wrap gap-1">
                  {sk.for_signing && <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-800 rounded">signing</span>}
                  {sk.for_transport_encryption && <span className="px-2 py-0.5 text-xs bg-green-100 text-green-800 rounded">transport-encrypt</span>}
                  {sk.for_storage_encryption && <span className="px-2 py-0.5 text-xs bg-green-100 text-green-800 rounded">storage-encrypt</span>}
                  {!sk.for_signing && !sk.for_transport_encryption && !sk.for_storage_encryption && (
                    <span className="px-2 py-0.5 text-xs bg-gray-200 text-gray-700 rounded">no flags</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="px-4 py-2 bg-gray-50 border-t border-gray-200 text-xs text-gray-500 font-mono">
        Self-signatures on primary: {inspection.primary_self_signatures} · Revocations: {inspection.primary_revocations}
      </div>
    </div>
  );
};

export const KeyDetailsModal: React.FC<Props> = ({ keyPair, onClose }) => {
  const [inspection, setInspection] = useState<CertInspection | null>(null);
  const [inspectLoading, setInspectLoading] = useState(true);
  const [inspectError, setInspectError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setInspectLoading(true);
    setInspectError(null);
    inspectCert(keyPair.publicKeyPgp)
      .then(result => {
        if (!cancelled) {
          setInspection(result);
          setInspectLoading(false);
        }
      })
      .catch(err => {
        if (!cancelled) {
          setInspectError(err?.message ?? String(err));
          setInspectLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, [keyPair.publicKeyPgp]);

  const compatibilityReport = useMemo(
    () => analyzePublicKeyCompatibility(keyPair.publicKeyPgp),
    [keyPair.publicKeyPgp]
  );
  const hasInfoNotes = compatibilityReport.checks.some(check => check.severity === 'info');

  const reportStyle = compatibilityReport.overall === 'fail'
    ? 'bg-red-50 border-l-4 border-red-400 text-red-800'
    : compatibilityReport.overall === 'warn'
      ? 'bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800'
      : 'bg-green-50 border-l-4 border-green-400 text-green-800';

  const reportTitle = compatibilityReport.overall === 'fail'
    ? 'Compatibility Check: FAIL'
    : compatibilityReport.overall === 'warn'
      ? 'Compatibility Check: WARNINGS'
      : hasInfoNotes
        ? 'Compatibility Check: PASS (NOTES)'
        : 'Compatibility Check: PASS';

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="p-6 sm:p-8">
            <div className="flex justify-between items-start mb-6">
              <h2 className="text-2xl sm:text-3xl font-bold text-gray-900">Key Pair Details</h2>
              <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition">&times;</button>
            </div>

            <div className="bg-green-50 border-l-4 border-green-400 p-4 rounded-md mb-6">
                <div className="flex">
                    <div className="flex-shrink-0">
                        <CheckCircleIcon />
                    </div>
                    <div className="ml-3">
                        <h3 className="text-sm font-medium text-green-800">Key Pair Generated Successfully</h3>
                        <div className="mt-2 text-sm text-green-700">
                            <p>Key ID: <span className="font-mono">{keyPair.fingerprint.replace(/\s/g, '').slice(-16)}</span>. Remember your passphrase if you set one!</p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-600 mb-1">User ID:</label>
                <input
                    type="text"
                    readOnly
                    value={keyPair.userId}
                    className="w-full p-2 bg-gray-100 border border-gray-300 rounded-md text-gray-800"
                />
              </div>

              <KeyBlock
                title="Public Key"
                content={keyPair.publicKeyPgp}
                filename={`public-key-${keyPair.fingerprint.replace(/\s/g, '').slice(-16)}.asc`}
              />

              {/* Packet-structure inspector — replaces the old raw-hex dumps */}
              <PacketInspector inspection={inspection} loading={inspectLoading} error={inspectError} />

              <div className={`${reportStyle} p-4 rounded-md`}>
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <ExclamationTriangleIcon />
                  </div>
                  <div className="ml-3">
                    <p className="font-bold">{reportTitle}</p>
                    <ul className="mt-2 text-sm space-y-1 list-disc list-inside">
                      {compatibilityReport.checks.map((check, index) => (
                        <li key={`${check.message}-${index}`}>
                          [{check.severity === 'info' ? 'NOTE' : check.severity.toUpperCase()}] {check.message}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              <div className="bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800 p-4 rounded-md">
                <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <ExclamationTriangleIcon />
                    </div>
                    <div className="ml-3">
                      <p className="font-bold">Private Key - DO NOT SHARE</p>
                      <p className="text-sm">This is your secret key. Keep it safe and do not share it with anyone.</p>
                      {keyPair.salt && <p className="text-sm mt-1">This key is protected by a passphrase. Enter it below to reveal the importable ASCII-armored block.</p>}
                    </div>
                </div>
              </div>

              <PrivateKeyPanel keyPair={keyPair} />
            </div>
        </div>
        <div className="bg-gray-50 px-6 py-4 flex justify-end rounded-b-xl border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-gray-200 text-gray-800 font-semibold rounded-lg hover:bg-gray-300 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

