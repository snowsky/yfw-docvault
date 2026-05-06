import React from 'react';

export function cx(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(' ');
}

export type PrimitiveProps<T extends keyof JSX.IntrinsicElements> = JSX.IntrinsicElements[T] & {
  className?: string;
};
