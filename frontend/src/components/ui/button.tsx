import { cx, type PrimitiveProps } from './primitives';

export function Button({
  className,
  variant,
  size,
  ...props
}: PrimitiveProps<'button'> & { variant?: 'outline' | 'ghost' | string; size?: 'sm' | 'icon' | string }) {
  return (
    <button
      className={cx(
        'dv-button',
        variant === 'outline' && 'dv-button-outline',
        variant === 'ghost' && 'dv-button-ghost',
        size === 'sm' && 'dv-button-sm',
        size === 'icon' && 'dv-button-icon',
        className,
      )}
      {...props}
    />
  );
}
