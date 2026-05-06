import React from 'react';
import { cx, type PrimitiveProps } from './primitives';

export function Dialog({ open, onOpenChange, children }: { open?: boolean; onOpenChange?: (open: boolean) => void; children: React.ReactNode }) {
  if (!open) return null;
  return (
    <div className="dv-dialog-backdrop" onClick={() => onOpenChange?.(false)}>
      {children}
    </div>
  );
}

export function DialogContent({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-dialog-content', className)} onClick={(event) => event.stopPropagation()} {...props} />;
}

export function DialogHeader({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-dialog-header', className)} {...props} />;
}

export function DialogTitle({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-dialog-title', className)} {...props} />;
}
