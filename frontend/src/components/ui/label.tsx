import { cx, type PrimitiveProps } from './primitives';

export function Label({ className, ...props }: PrimitiveProps<'label'>) {
  return <label className={cx('dv-label', className)} {...props} />;
}
