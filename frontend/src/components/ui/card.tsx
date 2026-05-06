import { cx, type PrimitiveProps } from './primitives';

export function Card({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card', className)} {...props} />;
}

export function CardHeader({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card-header', className)} {...props} />;
}

export function CardContent({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card-content', className)} {...props} />;
}

export function CardTitle({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-card-title', className)} {...props} />;
}
