import React from 'react';
import { AlertCircle, Download, ExternalLink, FileText, LockKeyhole, X } from 'lucide-react';

import { apiRequest } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

interface SharedDocVaultItem {
  record_type: 'docvault_item';
  id: number;
  category: string;
  title?: string | null;
  owner_name?: string | null;
  issuer?: string | null;
  expiry_date?: string | null;
  issue_date?: string | null;
  public_metadata: Record<string, any>;
  tags: string[];
  file_name?: string | null;
  file_mime_type?: string | null;
  file_size?: number | null;
  file_data_url?: string | null;
  sensitive_payload: Record<string, any>;
  notes?: string | null;
  unlocked: boolean;
  created_at: string;
  updated_at: string;
}

interface UnlockMethod {
  factor_id: string;
  label: string;
  input_label: string;
  placeholder: string;
  input_type: string;
}

interface FilePreviewDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  dataUrl?: string | null;
  fileName?: string | null;
  mimeType?: string | null;
}

function formatDate(value?: string | null) {
  if (!value) return '-';
  return new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function text(value: unknown) {
  return value == null || value === '' ? '-' : String(value).replace(/_/g, ' ');
}

function downloadDataUrl(dataUrl: string, filename: string) {
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = filename;
  a.click();
}

function downloadJson(item: SharedDocVaultItem) {
  const blob = new Blob([JSON.stringify(item, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `docvault-item-${item.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function dataUrlToBlob(dataUrl: string): Blob {
  const match = dataUrl.match(/^data:([^;,]+)?((?:;[^,]*)?),(.+)$/);
  if (!match) throw new Error('Unsupported file data');

  const [, mime = 'application/octet-stream', metadata, data] = match;
  if (metadata.includes(';base64')) {
    const binary = atob(data);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return new Blob([bytes], { type: mime });
  }

  return new Blob([decodeURIComponent(data)], { type: mime });
}

function downloadBlobUrl(url: string, fileName: string) {
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
}

function FilePreviewDialog({ open, onOpenChange, dataUrl, fileName, mimeType }: FilePreviewDialogProps) {
  const [objectUrl, setObjectUrl] = React.useState<string | null>(null);
  const [textPreview, setTextPreview] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const displayName = fileName || 'DocVault file';
  const type = mimeType || dataUrl?.match(/^data:([^;,]+)/)?.[1] || 'application/octet-stream';
  const isPdf = type === 'application/pdf' || displayName.toLowerCase().endsWith('.pdf');
  const isImage = type.startsWith('image/');
  const isText = type.startsWith('text/') || ['application/json', 'application/xml'].includes(type);

  React.useEffect(() => {
    if (!open || !dataUrl) {
      setObjectUrl(null);
      setTextPreview(null);
      setError(null);
      return undefined;
    }

    let url: string | null = null;
    setTextPreview(null);
    setError(null);

    try {
      const blob = dataUrlToBlob(dataUrl);
      url = URL.createObjectURL(blob);
      setObjectUrl(url);
      if (isText) {
        blob.text().then((value) => setTextPreview(value)).catch(() => setTextPreview(null));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to prepare file preview');
    }

    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [dataUrl, isText, open]);

  const canPreview = Boolean(objectUrl && (isPdf || isImage || isText));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl" style={{ width: 'min(1100px, 100%)' }}>
        <DialogHeader>
          <div className="flex items-start justify-between gap-3">
            <DialogTitle className="flex min-w-0 items-center gap-2">
              <FileText className="h-5 w-5 shrink-0" />
              <span className="truncate">{displayName}</span>
            </DialogTitle>
            <Button variant="ghost" size="icon" onClick={() => onOpenChange(false)} aria-label="Close file preview">
              <X className="h-4 w-4" />
            </Button>
          </div>
        </DialogHeader>

        {error && <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div>}

        {!error && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-muted-foreground">
              <span>{type}</span>
              {objectUrl && (
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" onClick={() => window.open(objectUrl, '_blank', 'noopener,noreferrer')}>
                    <ExternalLink className="mr-2 h-4 w-4" />
                    Open in new tab
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => downloadBlobUrl(objectUrl, displayName)}>
                    <Download className="mr-2 h-4 w-4" />
                    Download
                  </Button>
                </div>
              )}
            </div>

            {canPreview && objectUrl && isPdf && (
              <iframe title={displayName} src={objectUrl} className="h-[72vh] w-full rounded-md border bg-slate-50" />
            )}

            {canPreview && objectUrl && isImage && (
              <div className="flex max-h-[72vh] items-center justify-center overflow-auto rounded-md border bg-slate-50 p-3">
                <img src={objectUrl} alt={displayName} className="max-h-full max-w-full object-contain" />
              </div>
            )}

            {canPreview && isText && (
              <pre className="max-h-[72vh] overflow-auto rounded-md border bg-slate-50 p-3 text-xs">{textPreview || 'Loading preview...'}</pre>
            )}

            {!canPreview && (
              <div className="rounded-md border bg-slate-50 p-6 text-center text-sm text-muted-foreground">
                Preview is not available for this file type. You can open it in a new tab or download it.
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function SharedDocVaultItemPage() {
  const token = window.location.pathname.split('/shared/')[1]?.split('/')[0];
  const [item, setItem] = React.useState<SharedDocVaultItem | null>(null);
  const [unlockMethods, setUnlockMethods] = React.useState<UnlockMethod[]>([]);
  const [selectedFactorId, setSelectedFactorId] = React.useState('');
  const [unlockValue, setUnlockValue] = React.useState('');
  const [unlocking, setUnlocking] = React.useState(false);
  const [previewOpen, setPreviewOpen] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    if (!token) {
      setError('Shared link is missing a token');
      setLoading(false);
      return;
    }
    Promise.all([
      apiRequest<SharedDocVaultItem>(`/shared/${token}`),
      apiRequest<UnlockMethod[]>(`/shared/${token}/unlock-methods`).catch(() => []),
    ])
      .then(([record, methods]) => {
        setItem(record);
        setUnlockMethods(methods);
        setSelectedFactorId(methods[0]?.factor_id || '');
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load shared item'))
      .finally(() => setLoading(false));
  }, [token]);

  const selectedMethod = unlockMethods.find((method) => method.factor_id === selectedFactorId);
  const hasSensitivePayload = item && Object.keys(item.sensitive_payload || {}).length > 0;

  const unlockSharedItem = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!token || !selectedMethod || !unlockValue.trim()) return;
    setUnlocking(true);
    setError(null);
    try {
      const unlocked = await apiRequest<SharedDocVaultItem>(`/shared/${token}/unlock`, {
        method: 'POST',
        body: JSON.stringify({
          factor_id: selectedMethod.factor_id,
          user_input: unlockValue,
        }),
      });
      setItem(unlocked);
      setUnlockValue('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unlock failed');
    } finally {
      setUnlocking(false);
    }
  };

  const metadata = item?.public_metadata || {};
  const cloud = metadata.cloud_integration;

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-2xl flex-col justify-start p-6 pt-12">
      {loading && (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">Loading...</CardContent>
        </Card>
      )}

      {error && (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <AlertCircle className="h-8 w-8 text-red-600" />
            <p className="font-semibold">{error}</p>
            <p className="text-sm text-muted-foreground">This link may have expired or been revoked.</p>
          </CardContent>
        </Card>
      )}

      {item && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <LockKeyhole className="h-5 w-5" />
              DocVault Item
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div><span className="text-muted-foreground">Title</span><p className="font-medium">{text(item.title)}</p></div>
              <div><span className="text-muted-foreground">Type</span><p className="font-medium capitalize">{text(item.category)}</p></div>
              {item.owner_name && <div><span className="text-muted-foreground">Owner</span><p className="font-medium">{item.owner_name}</p></div>}
              {item.issuer && <div><span className="text-muted-foreground">Issuer</span><p className="font-medium">{item.issuer}</p></div>}
              {item.issue_date && <div><span className="text-muted-foreground">Issue date</span><p className="font-medium">{formatDate(item.issue_date)}</p></div>}
              {item.expiry_date && <div><span className="text-muted-foreground">Expiry date</span><p className="font-medium">{formatDate(item.expiry_date)}</p></div>}
              {item.file_name && <div><span className="text-muted-foreground">File</span><p className="font-medium">{item.file_name}</p></div>}
              {cloud?.provider_label && <div><span className="text-muted-foreground">Cloud source</span><p className="font-medium">{cloud.provider_label}</p></div>}
              {metadata.document_label && <div><span className="text-muted-foreground">Label</span><p className="font-medium capitalize">{text(metadata.document_label)}</p></div>}
              {metadata.approval_status && <div><span className="text-muted-foreground">Approval</span><p className="font-medium capitalize">{text(metadata.approval_status)}</p></div>}
              <div><span className="text-muted-foreground">Created</span><p className="font-medium">{formatDate(item.created_at)}</p></div>
            </div>

            {item.tags.length > 0 && (
              <div className="mt-4">
                <span className="text-sm text-muted-foreground">Tags</span>
                <div className="mt-2 flex flex-wrap gap-2">
                  {item.tags.map((tag) => (
                    <span key={tag} className="rounded-md border px-2 py-1 text-xs">{tag}</span>
                  ))}
                </div>
              </div>
            )}

            {!item.unlocked && (
              <form className="mt-5 space-y-3 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950" onSubmit={unlockSharedItem}>
                <div>
                  <div className="font-semibold">Open with an unlock method</div>
                  <p className="mt-1 text-amber-900">
                    Sensitive fields, notes, cloud URLs, and file contents are available after unlock.
                  </p>
                </div>
                {unlockMethods.length === 0 ? (
                  <p>No unlock method is configured for this vault item.</p>
                ) : (
                  <>
                    <Select value={selectedFactorId} onValueChange={setSelectedFactorId}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {unlockMethods.map((method) => (
                          <SelectItem key={method.factor_id} value={method.factor_id}>{method.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <div className="space-y-1.5">
                      <Label>{selectedMethod?.input_label || 'Unlock value'}</Label>
                      <Input
                        type={selectedMethod?.input_type || 'text'}
                        value={unlockValue}
                        onChange={(event) => setUnlockValue(event.target.value)}
                        placeholder={selectedMethod?.placeholder || 'Enter unlock value'}
                      />
                    </div>
                    <Button type="submit" disabled={unlocking || !unlockValue.trim()}>
                      {unlocking ? 'Unlocking...' : 'Unlock full item'}
                    </Button>
                  </>
                )}
              </form>
            )}

            {item.unlocked && (
              <div className="mt-5 space-y-4 rounded-lg border bg-slate-50 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="font-semibold">Full contents unlocked</div>
                    <p className="text-sm text-muted-foreground">Sensitive fields and downloadable contents are now visible.</p>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => downloadJson(item)}>Download JSON</Button>
                </div>

                {hasSensitivePayload && (
                  <div>
                    <div className="mb-2 text-sm font-semibold">Sensitive payload</div>
                    <pre className="max-h-80 overflow-auto rounded-md border bg-white p-3 text-xs">{JSON.stringify(item.sensitive_payload, null, 2)}</pre>
                  </div>
                )}

                {item.notes && (
                  <div>
                    <div className="mb-2 text-sm font-semibold">Notes</div>
                    <div className="whitespace-pre-wrap rounded-md border bg-white p-3 text-sm">{item.notes}</div>
                  </div>
                )}

                {cloud?.file_url && (
                  <div>
                    <div className="mb-2 text-sm font-semibold">Cloud document link</div>
                    <a className="break-all text-sm underline" href={cloud.file_url} target="_blank" rel="noreferrer">{cloud.file_url}</a>
                  </div>
                )}

                {item.file_data_url && (
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPreviewOpen(true)}>
                      Preview file
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => downloadDataUrl(item.file_data_url!, item.file_name || `docvault-item-${item.id}`)}
                    >
                      Download file
                    </Button>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <FilePreviewDialog
        open={previewOpen}
        onOpenChange={setPreviewOpen}
        dataUrl={item?.file_data_url}
        fileName={item?.file_name}
        mimeType={item?.file_mime_type}
      />

      <p className="mt-6 text-center text-xs text-muted-foreground">Powered by YourFinanceWORKS DocVault</p>
    </div>
  );
}
