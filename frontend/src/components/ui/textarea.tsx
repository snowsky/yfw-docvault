import { cx, type PrimitiveProps } from './primitives';

export function Textarea({ className, ...props }: PrimitiveProps<'textarea'>) {
  return <textarea className={cx('dv-textarea', className)} {...props} />;
}
