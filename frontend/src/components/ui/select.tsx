import React from 'react';
import { cx } from './primitives';

const SelectContext = React.createContext<{ value: string; onValueChange: (value: string) => void } | null>(null);

export function Select({ value, onValueChange, children }: { value: string; onValueChange: (value: string) => void; children: React.ReactNode }) {
  return <SelectContext.Provider value={{ value, onValueChange }}>{children}</SelectContext.Provider>;
}

export function SelectTrigger({ className, children }: { className?: string; children?: React.ReactNode }) {
  const ctx = React.useContext(SelectContext);
  const options = React.Children.toArray(children).flatMap(() => []);
  return <div className={cx('dv-select-shell', className)} data-value={ctx?.value}>{children || options}</div>;
}

export function SelectValue({ placeholder }: { placeholder?: string }) {
  const ctx = React.useContext(SelectContext);
  return <span>{ctx?.value || placeholder}</span>;
}

export function SelectContent({ children }: { children: React.ReactNode }) {
  const ctx = React.useContext(SelectContext);
  const options = React.Children.toArray(children)
    .filter(React.isValidElement)
    .map((child: any) => ({ value: child.props.value, label: child.props.children }));

  return (
    <select className="dv-select" value={ctx?.value || ''} onChange={(event) => ctx?.onValueChange(event.target.value)}>
      {options.map((option) => (
        <option key={option.value} value={option.value}>{option.label}</option>
      ))}
    </select>
  );
}

export function SelectItem(_props: { value: string; children: React.ReactNode; key?: React.Key }) {
  return null;
}
