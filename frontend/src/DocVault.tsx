import React from 'react';
import {
  AlertCircle,
  Archive,
  BadgeCheck,
  Cloud,
  Copy,
  CreditCard,
  ExternalLink,
  FileKey2,
  FileText,
  History,
  IdCard,
  KeyRound,
  Link2,
  Lock,
  PackageCheck,
  PenLine,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from 'lucide-react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { apiRequest } from '@/lib/api';

type Category = 'credit_card' | 'ssl_certificate' | 'id_card' | 'document' | 'secret';
type ExpiryStatus = 'expired' | 'expiring_soon' | 'valid';
type DocumentSource = 'local' | 'google_drive' | 'onedrive';
type UnlockMethod = 'mfa_google' | 'mfa_microsoft' | 'vault_password' | 'recovery_code' | 'local_confirmation';

interface UnlockSettings {
  enabled: Record<UnlockMethod, boolean>;
  googleAccount: string;
  microsoftAccount: string;
  passwordSet: boolean;
  recoveryCodeCount: number;
}

interface DocVaultEntry {
  id: number;
  category: Category;
  title: string;
  owner_name?: string | null;
  issuer?: string | null;
  expiry_date?: string | null;
  issue_date?: string | null;
  public_metadata: Record<string, any>;
  sensitive_payload: Record<string, any>;
  notes?: string | null;
  tags: string[];
  thumbnail_data_url?: string | null;
  file_name?: string | null;
  file_mime_type?: string | null;
  file_size?: number | null;
  file_data_url?: string | null;
  expiry_status: ExpiryStatus;
  days_delta?: number | null;
  alerting: boolean;
  sensitive_available: boolean;
  attachment_versions_count: number;
  signatures_count: number;
  created_at: string;
}

interface AttachmentVersion {
  id: number;
  entry_id: number;
  version: number;
  file_name: string;
  file_mime_type?: string | null;
  file_size?: number | null;
  checksum_sha256: string;
  change_note?: string | null;
  is_current: boolean;
  created_at: string;
}

interface SignatureRecord {
  id: number;
  entry_id: number;
  signer_name: string;
  signer_email?: string | null;
  provider: string;
  status: string;
  signature_reference?: string | null;
  signed_payload: Record<string, any>;
  signed_at: string;
}

interface MfaEnrollment {
  factor_id: string;
  label?: string | null;
  is_verified: boolean;
  created_at: string;
  verified_at?: string | null;
}

interface MfaSetup {
  factor_id: string;
  label?: string | null;
  secret: string;
  otpauth_uri: string;
  qr_data_url?: string | null;
  is_verified: boolean;
}

const emptyForm = {
  title: '',
  owner_name: '',
  issuer: '',
  expiry_date: '',
  issue_date: '',
  notes: '',
  tags: '',
  network: 'Visa',
  card_number: '',
  expiry_mm_yy: '',
  bank: '',
  domain: '',
  card_type: '',
  issuing_authority: '',
  password: '',
  private_key: '',
  retention_years: '',
  document_source: 'local' as DocumentSource,
  cloud_url: '',
  cloud_file_id: '',
  cloud_file_name: '',
};

const tabConfig: Array<{ id: Category; label: string; singularLabel: string; icon: React.ElementType }> = [
  { id: 'credit_card', label: 'Credit Cards', singularLabel: 'Credit Card', icon: CreditCard },
  { id: 'ssl_certificate', label: 'SSL Certificates', singularLabel: 'SSL Certificate', icon: ShieldCheck },
  { id: 'id_card', label: 'ID & Health Cards', singularLabel: 'ID or Health Card', icon: IdCard },
  { id: 'document', label: 'Documents', singularLabel: 'Document', icon: FileText },
  { id: 'secret', label: 'Passwords & Keys', singularLabel: 'Password or Key', icon: FileKey2 },
];

const networkStyles: Record<string, string> = {
  Visa: 'from-slate-950 to-blue-900',
  Mastercard: 'from-zinc-950 to-neutral-800',
  Amex: 'from-blue-700 to-sky-500',
  Discover: 'from-orange-600 to-amber-400',
  UnionPay: 'from-red-700 to-rose-500',
};

const unlockMethods: Array<{ id: UnlockMethod; label: string; factorId: string; inputLabel: string; placeholder: string; inputType?: string }> = [
  { id: 'mfa_google', label: 'Google Authenticator', factorId: 'google_auth', inputLabel: 'Authenticator code', placeholder: '6-digit code' },
  { id: 'mfa_microsoft', label: 'Microsoft Authenticator', factorId: 'ms_auth', inputLabel: 'Authenticator code', placeholder: '6-digit code' },
  { id: 'vault_password', label: 'Vault password', factorId: 'vault_password', inputLabel: 'Vault password', placeholder: 'Enter vault password', inputType: 'password' },
  { id: 'recovery_code', label: 'Recovery code', factorId: 'recovery_code', inputLabel: 'Recovery code', placeholder: 'Enter recovery code' },
  { id: 'local_confirmation', label: 'Local confirmation', factorId: 'local_fallback', inputLabel: 'Confirmation', placeholder: 'Type UNLOCK' },
];

const defaultUnlockSettings: UnlockSettings = {
  enabled: {
    mfa_google: true,
    mfa_microsoft: false,
    vault_password: false,
    recovery_code: false,
    local_confirmation: true,
  },
  googleAccount: '',
  microsoftAccount: '',
  passwordSet: false,
  recoveryCodeCount: 0,
};

function loadUnlockSettings(): UnlockSettings {
  try {
    const saved = window.localStorage.getItem('docvault.unlockSettings');
    if (!saved) return defaultUnlockSettings;
    const parsed = JSON.parse(saved);
    return {
      ...defaultUnlockSettings,
      ...parsed,
      enabled: { ...defaultUnlockSettings.enabled, ...(parsed.enabled || {}) },
    };
  } catch {
    return defaultUnlockSettings;
  }
}

function expiryPreview(category: Category, expiry: string): { status: ExpiryStatus; days: number | null } {
  if (!expiry) return { status: 'valid', days: null };
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const target = new Date(expiry);
  const days = Math.ceil((target.getTime() - today.getTime()) / 86400000);
  if (days < 0) return { status: 'expired', days };
  const windowDays = category === 'credit_card' ? 60 : 30;
  return { status: days <= windowDays ? 'expiring_soon' : 'valid', days };
}

function statusText(entry: Pick<DocVaultEntry, 'expiry_status' | 'days_delta'>) {
  if (entry.days_delta == null) return 'No expiry';
  if (entry.expiry_status === 'expired') return `${Math.abs(entry.days_delta)} days expired`;
  if (entry.expiry_status === 'expiring_soon') return `${entry.days_delta} days left`;
  return `${entry.days_delta} days left`;
}

function StatusBadge({ status, days }: { status: ExpiryStatus; days: number | null | undefined }) {
  const tone = status === 'expired'
    ? 'bg-red-100 text-red-700 border-red-200'
    : status === 'expiring_soon'
      ? 'bg-yellow-100 text-yellow-800 border-yellow-200'
      : 'bg-emerald-100 text-emerald-700 border-emerald-200';
  return <Badge variant="outline" className={tone}>{statusText({ expiry_status: status, days_delta: days })}</Badge>;
}

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

function fileSize(bytes?: number | null) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function cloudProviderLabel(provider?: string | null) {
  if (provider === 'google_drive') return 'Google Drive';
  if (provider === 'onedrive') return 'OneDrive';
  return 'Cloud';
}

function cloudIntegration(entry: Pick<DocVaultEntry, 'public_metadata'>) {
  return entry.public_metadata?.cloud_integration as
    | { provider?: DocumentSource; provider_label?: string; file_url?: string; file_id?: string; file_name?: string }
    | undefined;
}

function CardVisual({ form }: { form: typeof emptyForm }) {
  const number = form.card_number.replace(/\D/g, '');
  const last4 = number.slice(-4).padStart(4, '•');
  return (
    <div className={`aspect-[1.586/1] w-full rounded-xl bg-gradient-to-br ${networkStyles[form.network] || networkStyles.Visa} p-5 text-white shadow-lg`}>
      <div className="flex items-start justify-between">
        <div className="h-8 w-11 rounded-md bg-gradient-to-br from-yellow-200 to-yellow-600 shadow-inner" />
        <span className="text-lg font-semibold">{form.network}</span>
      </div>
      <div className="mt-8 font-mono text-xl tracking-widest">•••• •••• •••• {last4}</div>
      <div className="mt-6 flex justify-between text-xs uppercase">
        <div>
          <div className="text-white/60">Cardholder</div>
          <div className="font-semibold">{form.owner_name || 'NAME'}</div>
        </div>
        <div>
          <div className="text-white/60">Expires</div>
          <div className="font-semibold">{form.expiry_mm_yy || 'MM/YY'}</div>
        </div>
      </div>
    </div>
  );
}

export default function DocVault() {
  const [entries, setEntries] = React.useState<DocVaultEntry[]>([]);
  const [activeTab, setActiveTab] = React.useState<Category>('credit_card');
  const [query, setQuery] = React.useState('');
  const [tagFilter, setTagFilter] = React.useState('');
  const [categoryFilter, setCategoryFilter] = React.useState<Category | 'all'>('all');
  const [page, setPage] = React.useState(1);
  const [form, setForm] = React.useState(emptyForm);
  const [wizardOpen, setWizardOpen] = React.useState(false);
  const [wizardStep, setWizardStep] = React.useState(1);
  const [scanDraft, setScanDraft] = React.useState<Record<string, any> | null>(null);
  const [unlocking, setUnlocking] = React.useState<DocVaultEntry | null>(null);
  const [unlocked, setUnlocked] = React.useState<DocVaultEntry | null>(null);
  const [mfaCode, setMfaCode] = React.useState('');
  const [unlockMethod, setUnlockMethod] = React.useState<UnlockMethod>(() => {
    const saved = window.localStorage.getItem('docvault.unlockMethod') as UnlockMethod | null;
    return unlockMethods.some((method) => method.id === saved) ? saved! : 'mfa_google';
  });
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [unlockSettings, setUnlockSettings] = React.useState<UnlockSettings>(loadUnlockSettings);
  const [settingsMethod, setSettingsMethod] = React.useState<UnlockMethod>('mfa_google');
  const [passwordDraft, setPasswordDraft] = React.useState('');
  const [passwordConfirmDraft, setPasswordConfirmDraft] = React.useState('');
  const [recoveryCodesDraft, setRecoveryCodesDraft] = React.useState('');
  const [mfaEnrollments, setMfaEnrollments] = React.useState<MfaEnrollment[]>([]);
  const [mfaSetup, setMfaSetup] = React.useState<MfaSetup | null>(null);
  const [mfaVerifyCode, setMfaVerifyCode] = React.useState('');
  const [selectedFile, setSelectedFile] = React.useState<{ name: string; type: string; size: number; dataUrl: string } | null>(null);
  const [historyEntry, setHistoryEntry] = React.useState<DocVaultEntry | null>(null);
  const [versions, setVersions] = React.useState<AttachmentVersion[]>([]);
  const [signatureEntry, setSignatureEntry] = React.useState<DocVaultEntry | null>(null);
  const [signatures, setSignatures] = React.useState<SignatureRecord[]>([]);
  const [signatureForm, setSignatureForm] = React.useState({ signer_name: '', signer_email: '', provider: 'manual', signature_reference: '' });
  const [auditPackage, setAuditPackage] = React.useState<Record<string, any> | null>(null);
  const titleInputRef = React.useRef<HTMLInputElement | null>(null);

  const loadEntries = React.useCallback(async () => {
    const data = await apiRequest<DocVaultEntry[]>('/docvault');
    setEntries(data);
  }, []);

  React.useEffect(() => {
    loadEntries().catch((error) => toast.error(error.message || 'Failed to load DocVault'));
  }, [loadEntries]);

  const filtered = entries.filter((entry) => {
    const text = `${entry.title} ${entry.file_name || ''} ${entry.owner_name || ''} ${entry.issuer || ''} ${entry.tags.join(' ')}`.toLowerCase();
    const textMatch = !query || text.includes(query.toLowerCase());
    const tagMatch = !tagFilter || entry.tags.includes(tagFilter);
    const categoryMatch = categoryFilter === 'all' || entry.category === categoryFilter;
    return textMatch && tagMatch && categoryMatch;
  });
  const pageSize = 8;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const paginated = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);
  const alertCount = entries.filter((entry) => entry.alerting).length;
  const allTags = Array.from(new Set(entries.flatMap((entry) => entry.tags))).sort();
  const summary = {
    expired: entries.filter((entry) => entry.expiry_status === 'expired').length,
    expiring: entries.filter((entry) => entry.expiry_status === 'expiring_soon').length,
    valid: entries.filter((entry) => entry.expiry_status === 'valid').length,
  };
  const activeTabConfig = tabConfig.find((tab) => tab.id === activeTab) || tabConfig[0];
  const selectedUnlockMethod = unlockMethods.find((method) => method.id === unlockMethod) || unlockMethods[0];

  React.useEffect(() => {
    setPage(1);
  }, [query, tagFilter, categoryFilter]);

  React.useEffect(() => {
    window.localStorage.setItem('docvault.unlockMethod', unlockMethod);
  }, [unlockMethod]);

  React.useEffect(() => {
    window.localStorage.setItem('docvault.unlockSettings', JSON.stringify(unlockSettings));
  }, [unlockSettings]);

  React.useEffect(() => {
    if (!settingsOpen) return;
    loadMfaEnrollments().catch((error) => toast.error(error.message || 'Failed to load MFA enrollment'));
  }, [settingsOpen]);

  async function handleScan(file: File) {
    const dataUrl = await readFileAsDataUrl(file);
    const data = await apiRequest<any>('/docvault/scan-card', {
      method: 'POST',
      body: JSON.stringify({ category: activeTab === 'id_card' ? 'id_card' : 'credit_card', file_name: file.name, image_data_url: dataUrl }),
    });
    setScanDraft({ ...data.extracted, thumbnail_data_url: dataUrl, confidence: data.confidence });
  }

  function applyScanDraft() {
    if (!scanDraft) return;
    if (activeTab === 'credit_card') {
      setForm((prev) => ({
        ...prev,
        title: scanDraft.card_label || prev.title,
        network: scanDraft.network || prev.network,
        card_number: scanDraft.card_number || prev.card_number,
        expiry_mm_yy: scanDraft.expiry || prev.expiry_mm_yy,
        owner_name: scanDraft.cardholder_name || prev.owner_name,
        bank: scanDraft.bank || prev.bank,
      }));
    } else {
      setForm((prev) => ({
        ...prev,
        title: scanDraft.card_type || prev.title,
        owner_name: scanDraft.holder_name || prev.owner_name,
        expiry_date: scanDraft.expiry_date || prev.expiry_date,
        issuer: scanDraft.issuing_authority || prev.issuer,
        card_type: scanDraft.card_type || prev.card_type,
      }));
    }
    setSelectedFile(scanDraft.thumbnail_data_url ? { name: 'card-photo', type: 'image/*', size: 0, dataUrl: scanDraft.thumbnail_data_url } : null);
    setScanDraft(null);
  }

  async function handleFile(file: File) {
    const dataUrl = await readFileAsDataUrl(file);
    setSelectedFile({ name: file.name, type: file.type || 'application/octet-stream', size: file.size, dataUrl });
  }

  async function loadHistory(entry: DocVaultEntry) {
    setHistoryEntry(entry);
    const data = await apiRequest<AttachmentVersion[]>(`/docvault/${entry.id}/attachments`);
    setVersions(data);
  }

  async function loadSignatures(entry: DocVaultEntry) {
    setSignatureEntry(entry);
    const data = await apiRequest<SignatureRecord[]>(`/docvault/${entry.id}/signatures`);
    setSignatures(data);
  }

  async function createSignature() {
    if (!signatureEntry) return;
    if (!signatureForm.signer_name.trim()) {
      toast.error('Add signer name');
      return;
    }
    await apiRequest(`/docvault/${signatureEntry.id}/signatures`, {
      method: 'POST',
      body: JSON.stringify({
        signer_name: signatureForm.signer_name,
        signer_email: signatureForm.signer_email || null,
        provider: signatureForm.provider,
        signature_reference: signatureForm.signature_reference || null,
        status: 'signed',
      }),
    });
    setSignatureForm({ signer_name: '', signer_email: '', provider: 'manual', signature_reference: '' });
    await loadSignatures(signatureEntry);
    await loadEntries();
    toast.success('Signature recorded');
  }

  async function runRetention() {
    const data = await apiRequest<{ archived_count: number; archived_entry_ids: number[] }>('/docvault/retention/run', { method: 'POST' });
    await loadEntries();
    toast.success(`Archived ${data.archived_count} entries`);
  }

  async function buildAuditPackage() {
    const data = await apiRequest<Record<string, any>>('/docvault/audit-package', {
      method: 'POST',
      body: JSON.stringify({ include_archived: false, include_file_data: false }),
    });
    setAuditPackage(data);
    toast.success('Audit package generated');
  }

  async function loadMfaEnrollments() {
    const data = await apiRequest<MfaEnrollment[]>('/docvault/mfa/enrollments');
    setMfaEnrollments(data);
    setUnlockSettings((current) => {
      const next = { ...current, enabled: { ...current.enabled } };
      data.forEach((enrollment) => {
        if (enrollment.factor_id === 'google_auth' && enrollment.is_verified) {
          next.enabled.mfa_google = true;
          next.googleAccount = enrollment.label || next.googleAccount;
        }
        if (enrollment.factor_id === 'ms_auth' && enrollment.is_verified) {
          next.enabled.mfa_microsoft = true;
          next.microsoftAccount = enrollment.label || next.microsoftAccount;
        }
      });
      return next;
    });
  }

  async function startMfaEnrollment(method: UnlockMethod) {
    const factorId = unlockMethods.find((item) => item.id === method)?.factorId;
    if (factorId !== 'google_auth' && factorId !== 'ms_auth') return;
    const label = method === 'mfa_google' ? unlockSettings.googleAccount : unlockSettings.microsoftAccount;
    const setup = await apiRequest<MfaSetup>('/docvault/mfa/enrollments/setup', {
      method: 'POST',
      body: JSON.stringify({ factor_id: factorId, label: label || null }),
    });
    setMfaSetup(setup);
    setMfaVerifyCode('');
  }

  async function verifyMfaEnrollment() {
    if (!mfaSetup) return;
    const enrollment = await apiRequest<MfaEnrollment>('/docvault/mfa/enrollments/verify', {
      method: 'POST',
      body: JSON.stringify({ factor_id: mfaSetup.factor_id, code: mfaVerifyCode }),
    });
    await loadMfaEnrollments();
    const method: UnlockMethod = enrollment.factor_id === 'google_auth' ? 'mfa_google' : 'mfa_microsoft';
    updateUnlockEnabled(method, true);
    setMfaSetup(null);
    setMfaVerifyCode('');
    toast.success('MFA enrollment verified');
  }

  async function saveEntry() {
    const metadata: Record<string, any> = {};
    const sensitive: Record<string, any> = {};
    let title = form.title.trim();
    let issuer = form.issuer.trim();
    let expiryDate = form.expiry_date || null;

    if (activeTab === 'credit_card') {
      metadata.network = form.network;
      metadata.bank = form.bank;
      metadata.expiry_mm_yy = form.expiry_mm_yy;
      sensitive.card_number = form.card_number.replace(/\s/g, '');
      sensitive.last4 = sensitive.card_number.slice(-4);
      title = title || `${form.network} ${sensitive.last4 || 'Card'}`;
      issuer = issuer || form.bank;
      if (form.expiry_mm_yy.match(/^\d{2}\/\d{2}$/)) {
        const [month, year] = form.expiry_mm_yy.split('/');
        expiryDate = `20${year}-${month}-01`;
      }
    }
    if (activeTab === 'ssl_certificate') metadata.domain = form.domain;
    if (activeTab === 'id_card') metadata.card_type = form.card_type;
    if (activeTab === 'document') {
      if (form.retention_years) {
        metadata.retention_years = Number(form.retention_years);
        metadata.retention_start_date = new Date().toISOString().slice(0, 10);
      }
      if (form.document_source !== 'local') {
        if (!form.cloud_url.trim()) {
          toast.error(`Add a ${cloudProviderLabel(form.document_source)} share link`);
          return;
        }
        metadata.cloud_integration = {
          provider: form.document_source,
          file_url: form.cloud_url.trim(),
          file_id: form.cloud_file_id.trim() || null,
          file_name: form.cloud_file_name.trim() || title || null,
        };
        title = title || form.cloud_file_name.trim() || cloudProviderLabel(form.document_source);
      }
    }
    if (activeTab === 'secret') {
      sensitive.password = form.password;
      sensitive.private_key = form.private_key;
    }

    if (!title) {
      toast.error('Add a title before saving');
      return;
    }

    await apiRequest<DocVaultEntry>('/docvault', {
      method: 'POST',
      body: JSON.stringify({
        category: activeTab,
        title,
        owner_name: form.owner_name || null,
        issuer: issuer || null,
        expiry_date: expiryDate,
        issue_date: form.issue_date || null,
        public_metadata: metadata,
        sensitive_payload: sensitive,
        notes: form.notes || null,
        tags: form.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
        thumbnail_data_url: activeTab === 'id_card' ? selectedFile?.dataUrl : null,
        file_name: activeTab === 'document' && form.document_source !== 'local'
          ? form.cloud_file_name || title
          : selectedFile?.name || null,
        file_mime_type: activeTab === 'document' && form.document_source !== 'local'
          ? 'application/vnd.docvault.cloud-link'
          : selectedFile?.type || null,
        file_size: activeTab === 'document' && form.document_source !== 'local' ? null : selectedFile?.size || null,
        file_data_url: activeTab === 'document' && form.document_source === 'local' ? selectedFile?.dataUrl : null,
      }),
    });
    setForm(emptyForm);
    setSelectedFile(null);
    setWizardOpen(false);
    setWizardStep(1);
    await loadEntries();
    toast.success('Saved to DocVault');
  }

  async function deleteEntry(entry: DocVaultEntry) {
    await apiRequest(`/docvault/${entry.id}`, { method: 'DELETE' });
    await loadEntries();
    toast.success('Entry removed');
  }

  async function unlockEntry() {
    if (!unlocking) return;
    if (!unlockSettings.enabled[unlockMethod]) {
      toast.error('Enable this unlock method in settings first');
      return;
    }
    const data = await apiRequest<DocVaultEntry>(`/docvault/${unlocking.id}/unlock`, {
      method: 'POST',
      body: JSON.stringify({ factor_id: selectedUnlockMethod.factorId, user_input: mfaCode }),
    });
    setUnlocked(data);
    setUnlocking(null);
    setMfaCode('');
  }

  function updateUnlockEnabled(method: UnlockMethod, enabled: boolean) {
    setUnlockSettings((current) => ({ ...current, enabled: { ...current.enabled, [method]: enabled } }));
  }

  function savePasswordMethod() {
    if (passwordDraft.length < 8) {
      toast.error('Use at least 8 characters for the vault password');
      return;
    }
    if (passwordDraft !== passwordConfirmDraft) {
      toast.error('Vault passwords do not match');
      return;
    }
    setUnlockSettings((current) => ({
      ...current,
      passwordSet: true,
      enabled: { ...current.enabled, vault_password: true },
    }));
    setPasswordDraft('');
    setPasswordConfirmDraft('');
    toast.success('Vault password method set up');
  }

  function saveRecoveryCodes() {
    const codes = recoveryCodesDraft.split(/\s+/).map((code) => code.trim()).filter(Boolean);
    if (codes.length === 0) {
      toast.error('Add at least one recovery code');
      return;
    }
    setUnlockSettings((current) => ({
      ...current,
      recoveryCodeCount: codes.length,
      enabled: { ...current.enabled, recovery_code: true },
    }));
    setRecoveryCodesDraft('');
    toast.success('Recovery code method set up');
  }

  function startNewEntry(category: Category = activeTab) {
    setActiveTab(category);
    setForm(emptyForm);
    setSelectedFile(null);
    setScanDraft(null);
    setWizardStep(1);
    setWizardOpen(true);
    window.requestAnimationFrame(() => {
      titleInputRef.current?.focus();
    });
  }

  function closeWizard() {
    setWizardOpen(false);
    setWizardStep(1);
    setForm(emptyForm);
    setSelectedFile(null);
    setScanDraft(null);
  }

  const preview = expiryPreview(activeTab, form.expiry_date);

  return (
    <div className="min-h-screen bg-background px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase text-blue-700">
              <Archive className="h-4 w-4" />
              Secure records
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-slate-950">DocVault</h1>
            <p className="max-w-2xl text-sm text-muted-foreground">Manage credentials, IDs, certificates, and documents with expiry tracking and MFA-gated details.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={alertCount ? 'destructive' : 'outline'} className="gap-2 px-3 py-1.5">
              <AlertCircle className="h-4 w-4" />
              {alertCount} expiry alerts
            </Badge>
            <Button variant="outline" onClick={() => runRetention().catch((error) => toast.error(error.message || 'Retention run failed'))}>
              <Archive className="h-4 w-4" />
              Run retention
            </Button>
            <Button variant="outline" onClick={() => buildAuditPackage().catch((error) => toast.error(error.message || 'Audit package failed'))}>
              <PackageCheck className="h-4 w-4" />
              Audit package
            </Button>
            <Button variant="outline" onClick={() => setSettingsOpen(true)}>
              <Settings className="h-4 w-4" />
              Settings
            </Button>
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-slate-200 bg-white p-4 text-slate-900 shadow-sm">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs font-semibold uppercase text-slate-500">Total items</div>
              <Archive className="h-4 w-4 text-blue-700" />
            </div>
            <div className="mt-2 text-3xl font-bold">{entries.length}</div>
          </div>
          <div className="rounded-lg border border-red-200 bg-white p-4 text-red-800 shadow-sm">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs font-semibold uppercase text-red-600">Expired</div>
              <AlertCircle className="h-4 w-4" />
            </div>
            <div className="mt-2 text-3xl font-bold">{summary.expired}</div>
          </div>
          <div className="rounded-lg border border-yellow-200 bg-white p-4 text-yellow-900 shadow-sm">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs font-semibold uppercase text-yellow-700">Expiring Soon</div>
              <History className="h-4 w-4" />
            </div>
            <div className="mt-2 text-3xl font-bold">{summary.expiring}</div>
          </div>
          <div className="rounded-lg border border-emerald-200 bg-white p-4 text-emerald-800 shadow-sm">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs font-semibold uppercase text-emerald-700">Valid</div>
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div className="mt-2 text-3xl font-bold">{summary.valid}</div>
          </div>
        </div>

        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle className="text-lg">All items</CardTitle>
                <p className="mt-1 text-sm text-muted-foreground">{filtered.length} shown of {entries.length} records</p>
              </div>
              <Button onClick={() => startNewEntry(activeTab)}>
                <Plus className="h-4 w-4" />
                Add Item
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 md:grid-cols-[minmax(220px,1fr)_200px_200px]">
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input className="pl-9" placeholder="Search titles, files, owners, issuers, or tags" value={query} onChange={(e) => setQuery(e.target.value)} />
              </div>
              <Select value={categoryFilter} onValueChange={(value) => setCategoryFilter(value as Category | 'all')}>
                <SelectTrigger><SelectValue placeholder="Filter by type" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All types</SelectItem>
                  {tabConfig.map((tab) => <SelectItem key={tab.id} value={tab.id}>{tab.singularLabel}</SelectItem>)}
                </SelectContent>
              </Select>
              <Select value={tagFilter || 'all'} onValueChange={(value) => setTagFilter(value === 'all' ? '' : value)}>
                <SelectTrigger><SelectValue placeholder="Filter by tag" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All tags</SelectItem>
                  {allTags.map((tag) => <SelectItem key={tag} value={tag}>{tag}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-3">
              {paginated.map((entry) => {
                const entryConfig = tabConfig.find((tab) => tab.id === entry.category);
                const EntryIcon = entryConfig?.icon || FileText;
                return (
                  <Card key={entry.id} className="overflow-hidden transition hover:border-blue-200 hover:shadow-md">
                    <CardContent className="flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between">
                      <div className="flex min-w-0 gap-3">
                        {entry.thumbnail_data_url ? (
                          <img src={entry.thumbnail_data_url} alt="" className="h-16 w-24 rounded-md border object-cover" />
                        ) : (
                          <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-md border border-slate-200 bg-slate-50 text-slate-600">
                            <EntryIcon className="h-6 w-6" />
                          </div>
                        )}
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="truncate font-semibold">{entry.title}</h3>
                            <Badge variant="outline">{entryConfig?.singularLabel || 'Item'}</Badge>
                            <StatusBadge status={entry.expiry_status} days={entry.days_delta} />
                          </div>
                          <div className="mt-1 text-sm text-muted-foreground">
                            {entry.category === 'credit_card' && `${entry.public_metadata.network || 'Card'} ending ${entry.sensitive_payload.last4 || '----'}`}
                            {entry.category === 'ssl_certificate' && `${entry.public_metadata.domain || entry.title} · ${entry.issuer || 'Unknown issuer'}`}
                            {entry.category === 'id_card' && `${entry.public_metadata.card_type || 'ID'} · ${entry.issuer || 'Unknown authority'}`}
                            {entry.category === 'document' && (
                              cloudIntegration(entry)
                                ? `${entry.file_name || 'File'} · ${cloudProviderLabel(cloudIntegration(entry)?.provider)}`
                                : `${entry.file_name || 'File'} · ${fileSize(entry.file_size)}`
                            )}
                            {entry.category === 'secret' && 'Password / private key'}
                          </div>
                          <div className="mt-2 flex flex-wrap gap-1">
                            {entry.tags.map((tag) => <Badge key={tag} variant="secondary">{tag}</Badge>)}
                            {cloudIntegration(entry) && (
                              <Badge variant="outline" className="gap-1">
                                <Cloud className="h-3 w-3" />
                                {cloudProviderLabel(cloudIntegration(entry)?.provider)}
                              </Badge>
                            )}
                            {entry.attachment_versions_count > 0 && <Badge variant="outline">{entry.attachment_versions_count} versions</Badge>}
                            {entry.signatures_count > 0 && <Badge variant="outline">{entry.signatures_count} signatures</Badge>}
                          </div>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2 md:justify-end">
                        {entry.category === 'document' && (
                          <>
                            {cloudIntegration(entry)?.file_url && (
                              <Button variant="outline" size="sm" onClick={() => window.open(cloudIntegration(entry)?.file_url, '_blank')}>
                                <ExternalLink className="mr-2 h-4 w-4" />
                                Open
                              </Button>
                            )}
                            <Button variant="outline" size="sm" onClick={() => loadHistory(entry).catch((error) => toast.error(error.message || 'History failed'))}>
                              <History className="mr-2 h-4 w-4" />
                              History
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => loadSignatures(entry).catch((error) => toast.error(error.message || 'Signatures failed'))}>
                              <PenLine className="mr-2 h-4 w-4" />
                              Sign
                            </Button>
                          </>
                        )}
                        <Button variant="outline" size="sm" onClick={() => setUnlocking(entry)}>
                          <Lock className="mr-2 h-4 w-4" />
                          Details
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => deleteEntry(entry).catch((error) => toast.error(error.message || 'Delete failed'))}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
              {filtered.length === 0 && (
                <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">
                  <button
                    type="button"
                    aria-label="Create item"
                    className="flex h-12 w-12 items-center justify-center rounded-full border border-dashed border-slate-300 bg-white text-slate-700 shadow-sm transition hover:border-slate-900 hover:text-slate-950"
                    onClick={() => startNewEntry(activeTab)}
                  >
                    <Plus className="h-6 w-6" />
                  </button>
                  <div>No DocVault entries match the current filters.</div>
                  <Button variant="outline" size="sm" onClick={() => startNewEntry(activeTab)}>
                    <Plus className="h-4 w-4" />
                    Add Item
                  </Button>
                </div>
              )}
            </div>

            {filtered.length > 0 && (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-4 text-sm text-muted-foreground">
                <div>Page {safePage} of {pageCount}</div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={safePage === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" disabled={safePage === pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={wizardOpen} onOpenChange={(open) => !open && closeWizard()}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="h-5 w-5 text-blue-700" />
              Add item
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-5">
            <div className="grid gap-2 sm:grid-cols-3">
              {['Type', 'Details', 'Review'].map((label, index) => {
                const step = index + 1;
                return (
                  <div key={label} className={`rounded-md border p-3 text-sm ${wizardStep === step ? 'border-blue-200 bg-blue-50 text-blue-800' : 'border-slate-200 bg-white text-slate-500'}`}>
                    <div className="text-xs font-semibold uppercase">Step {step}</div>
                    <div className="font-semibold">{label}</div>
                  </div>
                );
              })}
            </div>

            {wizardStep === 1 && (
              <div className="grid gap-3 sm:grid-cols-2">
                {tabConfig.map((tab) => {
                  const Icon = tab.icon;
                  const selected = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      className={`flex items-center gap-3 rounded-lg border p-4 text-left transition ${selected ? 'border-blue-300 bg-blue-50 text-blue-900' : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'}`}
                      onClick={() => {
                        setActiveTab(tab.id);
                        setForm(emptyForm);
                        setSelectedFile(null);
                      }}
                    >
                      <span className="flex h-10 w-10 items-center justify-center rounded-md bg-slate-100">
                        <Icon className="h-5 w-5" />
                      </span>
                      <span>
                        <span className="block font-semibold">{tab.singularLabel}</span>
                        <span className="block text-sm text-muted-foreground">Create a new {tab.singularLabel.toLowerCase()} record</span>
                      </span>
                    </button>
                  );
                })}
              </div>
            )}

            {wizardStep === 2 && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div>
                    <div className="text-xs font-semibold uppercase text-slate-500">Selected type</div>
                    <div className="font-semibold text-slate-900">{activeTabConfig.singularLabel}</div>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => setWizardStep(1)}>Change</Button>
                </div>

                {activeTab === 'credit_card' && <CardVisual form={form} />}

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>Title</Label>
                    <Input ref={titleInputRef} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>Holder</Label>
                    <Input value={form.owner_name} onChange={(e) => setForm({ ...form, owner_name: e.target.value })} />
                  </div>
                </div>

                {activeTab === 'credit_card' && (
                  <>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <Label>Network</Label>
                        <Select value={form.network} onValueChange={(network) => setForm({ ...form, network })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            {Object.keys(networkStyles).map((network) => <SelectItem key={network} value={network}>{network}</SelectItem>)}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-1.5">
                        <Label>Expiry MM/YY</Label>
                        <Input placeholder="08/28" value={form.expiry_mm_yy} onChange={(e) => setForm({ ...form, expiry_mm_yy: e.target.value })} />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <Label>Card Number</Label>
                      <Input value={form.card_number} onChange={(e) => setForm({ ...form, card_number: e.target.value })} />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Bank</Label>
                      <Input value={form.bank} onChange={(e) => setForm({ ...form, bank: e.target.value })} />
                    </div>
                  </>
                )}

                {activeTab === 'ssl_certificate' && (
                  <>
                    <div className="space-y-1.5">
                      <Label>Domain</Label>
                      <Input value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value, title: e.target.value || form.title })} />
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <Label>Issuer</Label>
                        <Input value={form.issuer} onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
                      </div>
                      <div className="space-y-1.5">
                        <Label>Issue Date</Label>
                        <Input type="date" value={form.issue_date} onChange={(e) => setForm({ ...form, issue_date: e.target.value })} />
                      </div>
                    </div>
                  </>
                )}

                {activeTab === 'id_card' && (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Card Type</Label>
                      <Input value={form.card_type} onChange={(e) => setForm({ ...form, card_type: e.target.value })} />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Issuing Authority</Label>
                      <Input value={form.issuer} onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
                    </div>
                  </div>
                )}

                {activeTab === 'secret' && (
                  <>
                    <div className="space-y-1.5">
                      <Label>Password</Label>
                      <Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Private Key</Label>
                      <Textarea value={form.private_key} onChange={(e) => setForm({ ...form, private_key: e.target.value })} />
                    </div>
                  </>
                )}

                {activeTab === 'document' && (
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <Label>Document source</Label>
                      <Select
                        value={form.document_source}
                        onValueChange={(document_source) => setForm({ ...form, document_source: document_source as DocumentSource })}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="local">Local upload</SelectItem>
                          <SelectItem value="google_drive">Google Drive</SelectItem>
                          <SelectItem value="onedrive">OneDrive</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    {form.document_source !== 'local' && (
                      <>
                        <div className="space-y-1.5">
                          <Label className="flex items-center gap-2">
                            <Link2 className="h-4 w-4" />
                            {cloudProviderLabel(form.document_source)} share link
                          </Label>
                          <Input
                            placeholder={form.document_source === 'google_drive' ? 'https://drive.google.com/...' : 'https://1drv.ms/...'}
                            value={form.cloud_url}
                            onChange={(e) => setForm({ ...form, cloud_url: e.target.value })}
                          />
                        </div>
                        <div className="grid gap-3 sm:grid-cols-2">
                          <div className="space-y-1.5">
                            <Label>Cloud file name</Label>
                            <Input value={form.cloud_file_name} onChange={(e) => setForm({ ...form, cloud_file_name: e.target.value })} />
                          </div>
                          <div className="space-y-1.5">
                            <Label>Cloud file ID</Label>
                            <Input value={form.cloud_file_id} onChange={(e) => setForm({ ...form, cloud_file_id: e.target.value })} />
                          </div>
                        </div>
                      </>
                    )}

                    <div className="space-y-1.5">
                      <Label>Retention years</Label>
                      <Input
                        type="number"
                        min="1"
                        placeholder="7"
                        value={form.retention_years}
                        onChange={(e) => setForm({ ...form, retention_years: e.target.value })}
                      />
                    </div>
                  </div>
                )}

                {activeTab !== 'credit_card' && activeTab !== 'document' && activeTab !== 'secret' && (
                  <div className="space-y-1.5">
                    <Label>Expiry Date</Label>
                    <div className="flex gap-2">
                      <Input type="date" value={form.expiry_date} onChange={(e) => setForm({ ...form, expiry_date: e.target.value })} />
                      <StatusBadge status={preview.status} days={preview.days} />
                    </div>
                  </div>
                )}
              </div>
            )}

            {wizardStep === 3 && (
              <div className="space-y-4">
                {(activeTab === 'credit_card' || activeTab === 'id_card' || (activeTab === 'document' && form.document_source === 'local')) && (
                  <div className="rounded-lg border border-dashed p-4">
                    <Label className="mb-2 flex items-center gap-2">
                      <Upload className="h-4 w-4" />
                      {activeTab === 'document' ? 'Upload Document' : 'AI Scan'}
                    </Label>
                    <Input
                      type="file"
                      accept={activeTab === 'document' ? undefined : 'image/*'}
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        if (!file) return;
                        if (activeTab === 'document') handleFile(file);
                        else handleScan(file).catch((error) => toast.error(error.message || 'Scan failed'));
                      }}
                    />
                    {selectedFile && <div className="mt-2 text-xs text-muted-foreground">{selectedFile.name} · {fileSize(selectedFile.size)}</div>}
                  </div>
                )}

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>Tags</Label>
                    <Input placeholder="finance, renewal, personal" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500">Ready to save</div>
                    <div className="mt-1 font-semibold text-slate-900">{form.title || activeTabConfig.singularLabel}</div>
                    <div className="text-muted-foreground">{activeTabConfig.singularLabel}</div>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label>Notes</Label>
                  <Textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-4">
              <Button variant="ghost" onClick={closeWizard}>Cancel</Button>
              <div className="flex gap-2">
                <Button variant="outline" disabled={wizardStep === 1} onClick={() => setWizardStep((step) => Math.max(1, step - 1))}>
                  Back
                </Button>
                {wizardStep < 3 ? (
                  <Button onClick={() => setWizardStep((step) => Math.min(3, step + 1))}>Next</Button>
                ) : (
                  <Button onClick={() => saveEntry().catch((error) => toast.error(error.message || 'Save failed'))}>
                    Save to Vault
                  </Button>
                )}
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!scanDraft} onOpenChange={(open) => !open && setScanDraft(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Sparkles className="h-5 w-5" /> Confirm AI scan</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            {scanDraft && Object.entries(scanDraft).filter(([key]) => key !== 'thumbnail_data_url').map(([key, value]) => (
              <div key={key} className="grid grid-cols-[150px_1fr] gap-2 text-sm">
                <span className="font-medium capitalize text-muted-foreground">{key.replace(/_/g, ' ')}</span>
                <Input value={String(value ?? '')} onChange={(event) => setScanDraft({ ...scanDraft, [key]: event.target.value })} />
              </div>
            ))}
            <Button className="w-full" onClick={applyScanDraft}>Use corrected values</Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              Vault settings
            </DialogTitle>
          </DialogHeader>
          <div className="grid gap-5 lg:grid-cols-[240px_minmax(0,1fr)]">
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>Default unlock method</Label>
                <Select value={unlockMethod} onValueChange={(value) => setUnlockMethod(value as UnlockMethod)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {unlockMethods.map((method) => (
                      <SelectItem key={method.id} value={method.id}>{method.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                {unlockMethods.map((method) => (
                  <button
                    key={method.id}
                    type="button"
                    className={`rounded-lg border p-3 text-left transition ${settingsMethod === method.id ? 'border-blue-300 bg-blue-50 text-blue-900' : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'}`}
                    onClick={() => setSettingsMethod(method.id)}
                  >
                    <div className="font-semibold">{method.label}</div>
                    <div className="text-sm text-muted-foreground">{unlockSettings.enabled[method.id] ? 'Enabled' : 'Not set up'}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-4 rounded-lg border border-slate-200 bg-white p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-lg font-semibold text-slate-950">{unlockMethods.find((method) => method.id === settingsMethod)?.label}</div>
                  <div className="text-sm text-muted-foreground">Set up and enable this unlock method.</div>
                </div>
                <label className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                  <input
                    type="checkbox"
                    checked={unlockSettings.enabled[settingsMethod]}
                    onChange={(event) => updateUnlockEnabled(settingsMethod, event.target.checked)}
                  />
                  Enabled
                </label>
              </div>

              {settingsMethod === 'mfa_google' && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-muted-foreground">
                    Scan the QR code with Google Authenticator, then enter the current 6-digit code to verify enrollment.
                  </div>
                  <div className="space-y-1.5">
                    <Label>Account label</Label>
                    <Input
                      placeholder="name@example.com"
                      value={unlockSettings.googleAccount}
                      onChange={(event) => setUnlockSettings((current) => ({ ...current, googleAccount: event.target.value }))}
                    />
                  </div>
                  {mfaEnrollments.find((enrollment) => enrollment.factor_id === 'google_auth' && enrollment.is_verified) && (
                    <Badge variant="outline">Verified enrollment</Badge>
                  )}
                  {mfaSetup?.factor_id === 'google_auth' && (
                    <div className="space-y-3 rounded-lg border border-blue-100 bg-blue-50 p-3">
                      {mfaSetup.qr_data_url ? (
                        <img src={mfaSetup.qr_data_url} alt="Google Authenticator QR code" className="h-44 w-44 rounded-md border bg-white p-2" />
                      ) : (
                        <div className="rounded-md border bg-white p-3 text-sm text-muted-foreground">QR generation is unavailable. Enter the manual secret in your authenticator app.</div>
                      )}
                      <div className="break-all rounded-md bg-white p-2 font-mono text-xs text-slate-700">{mfaSetup.secret}</div>
                      <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                        <Input placeholder="6-digit code" value={mfaVerifyCode} onChange={(event) => setMfaVerifyCode(event.target.value)} />
                        <Button onClick={() => verifyMfaEnrollment().catch((error) => toast.error(error.message || 'Verification failed'))}>Verify</Button>
                      </div>
                    </div>
                  )}
                  <Button onClick={() => startMfaEnrollment('mfa_google').catch((error) => toast.error(error.message || 'Enrollment failed'))}>
                    Generate QR code
                  </Button>
                </div>
              )}

              {settingsMethod === 'mfa_microsoft' && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-muted-foreground">
                    Scan the QR code with Microsoft Authenticator, then enter the current 6-digit code to verify enrollment.
                  </div>
                  <div className="space-y-1.5">
                    <Label>Account label</Label>
                    <Input
                      placeholder="name@example.com"
                      value={unlockSettings.microsoftAccount}
                      onChange={(event) => setUnlockSettings((current) => ({ ...current, microsoftAccount: event.target.value }))}
                    />
                  </div>
                  {mfaEnrollments.find((enrollment) => enrollment.factor_id === 'ms_auth' && enrollment.is_verified) && (
                    <Badge variant="outline">Verified enrollment</Badge>
                  )}
                  {mfaSetup?.factor_id === 'ms_auth' && (
                    <div className="space-y-3 rounded-lg border border-blue-100 bg-blue-50 p-3">
                      {mfaSetup.qr_data_url ? (
                        <img src={mfaSetup.qr_data_url} alt="Microsoft Authenticator QR code" className="h-44 w-44 rounded-md border bg-white p-2" />
                      ) : (
                        <div className="rounded-md border bg-white p-3 text-sm text-muted-foreground">QR generation is unavailable. Enter the manual secret in your authenticator app.</div>
                      )}
                      <div className="break-all rounded-md bg-white p-2 font-mono text-xs text-slate-700">{mfaSetup.secret}</div>
                      <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                        <Input placeholder="6-digit code" value={mfaVerifyCode} onChange={(event) => setMfaVerifyCode(event.target.value)} />
                        <Button onClick={() => verifyMfaEnrollment().catch((error) => toast.error(error.message || 'Verification failed'))}>Verify</Button>
                      </div>
                    </div>
                  )}
                  <Button onClick={() => startMfaEnrollment('mfa_microsoft').catch((error) => toast.error(error.message || 'Enrollment failed'))}>
                    Generate QR code
                  </Button>
                </div>
              )}

              {settingsMethod === 'vault_password' && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-muted-foreground">
                    Set a vault password for standalone unlock. In this local plugin view, only setup state is stored locally.
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Vault password</Label>
                      <Input type="password" value={passwordDraft} onChange={(event) => setPasswordDraft(event.target.value)} />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Confirm password</Label>
                      <Input type="password" value={passwordConfirmDraft} onChange={(event) => setPasswordConfirmDraft(event.target.value)} />
                    </div>
                  </div>
                  {unlockSettings.passwordSet && <Badge variant="outline">Password configured</Badge>}
                  <Button onClick={savePasswordMethod}>Save vault password</Button>
                </div>
              )}

              {settingsMethod === 'recovery_code' && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-muted-foreground">
                    Add recovery codes separated by spaces or new lines. Store them somewhere safe before closing settings.
                  </div>
                  <div className="space-y-1.5">
                    <Label>Recovery codes</Label>
                    <Textarea
                      placeholder={'CODE-1234\nCODE-5678'}
                      value={recoveryCodesDraft}
                      onChange={(event) => setRecoveryCodesDraft(event.target.value)}
                    />
                  </div>
                  {unlockSettings.recoveryCodeCount > 0 && <Badge variant="outline">{unlockSettings.recoveryCodeCount} codes configured</Badge>}
                  <Button onClick={saveRecoveryCodes}>Save recovery codes</Button>
                </div>
              )}

              {settingsMethod === 'local_confirmation' && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-muted-foreground">
                    Local confirmation is intended for standalone development and self-hosted fallback mode. Users type UNLOCK to reveal details.
                  </div>
                  <Button onClick={() => {
                    updateUnlockEnabled('local_confirmation', true);
                    toast.success('Local confirmation enabled');
                  }}>
                    Enable local confirmation
                  </Button>
                </div>
              )}

              <div className="flex justify-end border-t border-slate-200 pt-4">
                <Button onClick={() => setSettingsOpen(false)}>Done</Button>
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!unlocking} onOpenChange={(open) => !open && setUnlocking(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Lock className="h-5 w-5" /> Unlock vault details</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="rounded-lg border bg-muted p-3 text-sm text-muted-foreground">
              Unlock with {selectedUnlockMethod.label}. You can change the default in vault settings.
            </div>
            <Select value={unlockMethod} onValueChange={(value) => setUnlockMethod(value as UnlockMethod)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {unlockMethods.map((method) => (
                  <SelectItem key={method.id} value={method.id}>{method.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="space-y-1.5">
              <Label>{selectedUnlockMethod.inputLabel}</Label>
              <Input
                type={selectedUnlockMethod.inputType || 'text'}
                value={mfaCode}
                onChange={(event) => setMfaCode(event.target.value)}
                placeholder={selectedUnlockMethod.placeholder}
              />
            </div>
            <Button className="w-full" onClick={() => unlockEntry().catch((error) => toast.error(error.message || 'Unlock failed'))}>Unlock</Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!unlocked} onOpenChange={(open) => !open && setUnlocked(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><BadgeCheck className="h-5 w-5" /> Vault details</DialogTitle>
          </DialogHeader>
          {unlocked && (
            <div className="space-y-3">
              <div className="rounded-lg border p-3">
                <div className="font-semibold">{unlocked.title}</div>
                <div className="text-sm text-muted-foreground">{unlocked.notes || 'No private notes'}</div>
              </div>
              {cloudIntegration(unlocked)?.file_url && (
                <div className="rounded-lg border p-3 text-sm">
                  <div className="font-medium">{cloudProviderLabel(cloudIntegration(unlocked)?.provider)}</div>
                  <div className="mt-1 break-all text-muted-foreground">{cloudIntegration(unlocked)?.file_url}</div>
                  {cloudIntegration(unlocked)?.file_id && (
                    <div className="mt-1 font-mono text-xs text-muted-foreground">{cloudIntegration(unlocked)?.file_id}</div>
                  )}
                </div>
              )}
              <pre className="max-h-72 overflow-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(unlocked.sensitive_payload, null, 2)}</pre>
              {cloudIntegration(unlocked)?.file_url && (
                <Button variant="outline" onClick={() => window.open(cloudIntegration(unlocked)?.file_url, '_blank')}>
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open cloud file
                </Button>
              )}
              {unlocked.file_data_url && <Button variant="outline" onClick={() => window.open(unlocked.file_data_url!, '_blank')}>Open file</Button>}
              <Button
                variant="outline"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(unlocked.sensitive_payload, null, 2));
                  toast.success('Copied vault details');
                }}
              >
                <Copy className="mr-2 h-4 w-4" />
                Copy details
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={!!historyEntry} onOpenChange={(open) => !open && setHistoryEntry(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><History className="h-5 w-5" /> Attachment history</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="font-semibold">{historyEntry?.title}</div>
            {versions.map((version) => (
              <div key={version.id} className="rounded-lg border p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-medium">v{version.version} · {version.file_name}</div>
                  {version.is_current && <Badge variant="outline">Current</Badge>}
                </div>
                <div className="mt-1 text-muted-foreground">{fileSize(version.file_size)} · {new Date(version.created_at).toLocaleString()}</div>
                <div className="mt-1 font-mono text-xs text-muted-foreground">{version.checksum_sha256}</div>
                {version.change_note && <div className="mt-2">{version.change_note}</div>}
              </div>
            ))}
            {versions.length === 0 && <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">No attachment versions yet.</div>}
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!signatureEntry} onOpenChange={(open) => !open && setSignatureEntry(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><PenLine className="h-5 w-5" /> Digital signatures</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Signer name</Label>
                <Input value={signatureForm.signer_name} onChange={(e) => setSignatureForm({ ...signatureForm, signer_name: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>Signer email</Label>
                <Input value={signatureForm.signer_email} onChange={(e) => setSignatureForm({ ...signatureForm, signer_email: e.target.value })} />
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Provider</Label>
                <Input value={signatureForm.provider} onChange={(e) => setSignatureForm({ ...signatureForm, provider: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>Signature reference</Label>
                <Input value={signatureForm.signature_reference} onChange={(e) => setSignatureForm({ ...signatureForm, signature_reference: e.target.value })} />
              </div>
            </div>
            <Button className="w-full" onClick={() => createSignature().catch((error) => toast.error(error.message || 'Signature failed'))}>Record signature</Button>
            <div className="space-y-2">
              {signatures.map((signature) => (
                <div key={signature.id} className="rounded-lg border p-3 text-sm">
                  <div className="font-medium">{signature.signer_name} · {signature.provider}</div>
                  <div className="text-muted-foreground">{signature.signer_email || 'No email'} · {new Date(signature.signed_at).toLocaleString()}</div>
                  <div className="mt-1 font-mono text-xs text-muted-foreground">{signature.signed_payload?.checksum_sha256}</div>
                </div>
              ))}
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!auditPackage} onOpenChange={(open) => !open && setAuditPackage(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><PackageCheck className="h-5 w-5" /> Audit package</DialogTitle>
          </DialogHeader>
          {auditPackage && (
            <div className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border p-3">
                  <div className="text-xs uppercase text-muted-foreground">Entries</div>
                  <div className="text-2xl font-bold">{auditPackage.manifest?.entry_count}</div>
                </div>
                <div className="rounded-lg border p-3 sm:col-span-2">
                  <div className="text-xs uppercase text-muted-foreground">Package checksum</div>
                  <div className="truncate font-mono text-xs">{auditPackage.manifest?.package_checksum_sha256}</div>
                </div>
              </div>
              <pre className="max-h-80 overflow-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(auditPackage, null, 2)}</pre>
              <Button
                variant="outline"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(auditPackage, null, 2));
                  toast.success('Copied audit package');
                }}
              >
                <Copy className="mr-2 h-4 w-4" />
                Copy package
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
