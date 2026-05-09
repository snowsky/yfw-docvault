import React from 'react';

import { cx, type PrimitiveProps } from './primitives';

export const Card = React.forwardRef<HTMLDivElement, PrimitiveProps<'div'>>(
  ({ className, ...props }, ref) => <div ref={ref} className={cx('dv-card', className)} {...props} />,
);

Card.displayName = 'Card';

export function CardHeader({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card-header', className)} {...props} />;
}

export function CardContent({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card-content', className)} {...props} />;
}

export function CardTitle({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card-title', className)} {...props} />;
}
