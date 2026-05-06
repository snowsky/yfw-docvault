import { cx, type PrimitiveProps } from './primitives';

export function Input({ className, ...props }: PrimitiveProps<'input'>) {
  return <input className={cx('dv-input', className)} {...props} />;
}
