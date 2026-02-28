import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'GitAGrip',
  description: 'GitHub repository scoring platform',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
