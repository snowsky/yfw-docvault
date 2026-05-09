import React from 'react';

import { cx, type PrimitiveProps } from './primitives';

export const Input = React.forwardRef<HTMLInputElement, PrimitiveProps<'input'>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cx('dv-input', className)} {...props} />,
);

Input.displayName = 'Input';
