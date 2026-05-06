import { cx, type PrimitiveProps } from './primitives';

export function Badge({ className, variant, ...props }: PrimitiveProps<'span'> & { variant?: string }) {
  return (
    <span
      className={cx(
        'dv-badge',
        variant === 'destructive' && 'dv-badge-danger',
        variant === 'outline' && 'dv-badge-outline',
        className,
      )}
      {...props}
    />
  );
}
