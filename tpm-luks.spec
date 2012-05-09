Name:		tpm-luks
Version:	0.1
Release:	1%{?dist}
Summary:	Utility for storing your LUKS key in TPM NVRAM

Group:		Security
License:	GPLv2
#URL:
Source0:	tpm-luks-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	automake autoconf libtool
Requires:	cryptsetup dracut

%description


%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc



%changelog
