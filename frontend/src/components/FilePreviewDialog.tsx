import React from 'react';
import { Download, ExternalLink, FileText, X } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';

interface FilePreviewDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  dataUrl?: string | null;
  fileName?: string | null;
  mimeType?: string | null;
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

export function FilePreviewDialog({ open, onOpenChange, dataUrl, fileName, mimeType }: FilePreviewDialogProps) {
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
