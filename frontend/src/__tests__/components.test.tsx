import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';

function withRouter(ui: React.ReactNode) {
  return <BrowserRouter>{ui}</BrowserRouter>;
}

describe('StatCard', () => {
  it('renders label and value', () => {
    render(withRouter(<StatCard label="Total Flows" value={42} />));
    expect(screen.getByText('Total Flows')).toBeDefined();
    expect(screen.getByText('42')).toBeDefined();
  });

  it('renders string value', () => {
    render(withRouter(<StatCard label="Status" value="healthy" />));
    expect(screen.getByText('healthy')).toBeDefined();
  });
});

describe('SeverityBadge', () => {
  it('renders CRITICAL', () => {
    render(withRouter(<SeverityBadge severity="CRITICAL" />));
    expect(screen.getByText('CRITICAL')).toBeDefined();
  });

  it('renders LOW', () => {
    render(withRouter(<SeverityBadge severity="LOW" />));
    expect(screen.getByText('LOW')).toBeDefined();
  });
});

describe('EmptyState', () => {
  it('renders message', () => {
    render(withRouter(<EmptyState message="No data available" />));
    expect(screen.getByText('No data available')).toBeDefined();
  });
});
