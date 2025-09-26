import { type NextRequest, NextResponse } from 'next/server';
import { rootDomain } from '@/lib/utils';
import { getToken } from 'next-auth/jwt';

function extractSubdomain(request: NextRequest): string | null {
  const url = request.url;
  const hostname = (request.headers.get('host') || '').split(':')[0];
  const isLocal = url.includes('localhost') || url.includes('127.0.0.1');
  if (isLocal) {
    return hostname.startsWith('interviewer.') || /http:\/\/interviewer\.localhost/.test(url)
      ? 'interviewer'
      : null;
  }
  const rootDomainHost = rootDomain.split(':')[0];
  return hostname === `interviewer.${rootDomainHost}` ? 'interviewer' : null;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const subdomain = extractSubdomain(request);
  let token: any = null;
  try {
    token = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET });
  } catch {
    token = null;
  }
  const isAuthenticated = Boolean(token);
  const role = (token as any)?.role as 'interviewer' | 'user' | undefined;

  // interviewer subdomain: enforce auth before any rewrites
  if (subdomain === 'interviewer') {
    const effectivePath = pathname === '/' ? '/interviewer' : pathname;
    const isPublicPath =
      effectivePath.startsWith('/interviewer/sign-in') ||
      effectivePath.startsWith('/interviewer/signup') ||
      pathname === '/sign-in';
    if (!isAuthenticated && !isPublicPath) {
      const port = request.nextUrl.port ? `:${request.nextUrl.port}` : '';
      const rootDomainHost = rootDomain.split(':')[0];
      const origin = `${request.nextUrl.protocol}//${rootDomainHost}${port}`;
      return NextResponse.redirect(new URL('/sign-in', origin));
    }
    // Prevent redirect loops on /sign-in at interviewer subdomain
    if (!isAuthenticated && pathname === '/sign-in') {
      return NextResponse.next();
    }
    if (isAuthenticated && role !== 'interviewer' && !isPublicPath) {
      return NextResponse.redirect(new URL('/', request.url));
    }
    // perform rewrites after auth check
    const target = pathname === '/' ? '/interviewer' : (!pathname.startsWith('/interviewer') ? `/interviewer${pathname}` : null);
    return target ? NextResponse.rewrite(new URL(target, request.url)) : NextResponse.next();
  }

  // root domain auth-based routing
  if (pathname === '/') {
    if (isAuthenticated) {
      return NextResponse.redirect(new URL('/app', request.url));
    }
    return NextResponse.next(); // show landing page
  }

  // protect app: if not logged in, redirect to landing
  if (pathname.startsWith('/app') && !isAuthenticated) {
    return NextResponse.redirect(new URL('/', request.url));
  }

  // on the root domain, allow normal access
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all paths except for:
     * 1. /api routes
     * 2. /_next (Next.js internals)
     * 3. all root files inside /public (e.g. /favicon.ico)
     */
    '/((?!api|_next|[\\w-]+\\.\\w+).*)'
  ]
};