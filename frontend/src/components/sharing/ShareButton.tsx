import React from 'react';
import { Copy, Link, Share2 } from 'lucide-react';
import { toast } from 'sonner';

import { apiRequest } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type ShareAccessType = 'public' | 'password' | 'question';
type RecordType = 'docvault_item';

interface ShareTokenResponse {
  token: string;
  share_url: string;
  expires_at: string | null;
}

interface ShareButtonProps {
  recordType: RecordType;
  recordId: number;
  variant?: 'default' | 'outline' | 'ghost';
  size?: 'default' | 'sm' | 'lg' | 'icon';
}

export function ShareButton({ recordType, recordId, variant = 'outline', size = 'sm' }: ShareButtonProps) {
  const [open, setOpen] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [shareUrl, setShareUrl] = React.useState('');
  const [expiresInHours, setExpiresInHours] = React.useState(24);

  const generateLink = async () => {
    setLoading(true);
    try {
      const response = await apiRequest<ShareTokenResponse>('/share-tokens/', {
        method: 'POST',
        body: JSON.stringify({
          record_type: recordType,
          record_id: recordId,
          access_type: 'public' as ShareAccessType,
          expires_in_hours: expiresInHours,
        }),
      });
      setShareUrl(`${window.location.origin}/shared/${response.token}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to generate share link');
    } finally {
      setLoading(false);
    }
  };

  const copyLink = async () => {
    if (!shareUrl) return;
    try {
      await navigator.clipboard.writeText(shareUrl);
      toast.success('Link copied to clipboard');
    } catch {
      toast.error('Failed to copy link');
    }
  };

  return (
    <>
      <Button variant={variant} size={size} onClick={() => setOpen(true)}>
        <Share2 className="mr-2 h-4 w-4" />
        Share
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Link className="h-4 w-4" />
              Share link
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!shareUrl ? (
              <>
                <div className="space-y-2">
                  <Label htmlFor="share-expiration">Expiration hours</Label>
                  <Input
                    id="share-expiration"
                    type="number"
                    min={1}
                    max={8760}
                    value={expiresInHours}
                    onChange={(event) => setExpiresInHours(Number(event.target.value))}
                  />
                </div>
                <p className="text-sm text-muted-foreground">
                  Shared DocVault items open with a configured unlock method before sensitive details or file contents are shown.
                </p>
                <div className="flex justify-end gap-2">
                  <Button variant="outline" size="sm" onClick={() => setOpen(false)}>
                    Cancel
                  </Button>
                  <Button size="sm" onClick={generateLink} disabled={loading}>
                    {loading ? 'Generating...' : 'Generate link'}
                  </Button>
                </div>
              </>
            ) : (
              <>
                <div className="flex gap-2">
                  <Input readOnly value={shareUrl} className="font-mono text-xs" />
                  <Button size="icon" variant="outline" onClick={copyLink} title="Copy link">
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
                <div className="flex justify-end">
                  <Button size="sm" onClick={() => setOpen(false)}>
                    Done
                  </Button>
                </div>
              </>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
