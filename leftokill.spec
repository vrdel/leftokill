%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

Name:           leftokill
Version:        0.1.0
Release:        1%{?dist}.srce
Summary:        Unix daemon that cleans the processes/threads left by the job scheduler
Group:          System Environment/Daemons
License:        GPL
URL:            https://github.com/vrdel/leftokill 
Source0:        leftokill-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch 
Requires:       python-psutil 


%description
Unix daemon that cleans the processes/threads left by the job scheduler


%prep
%setup -q


%build
%{__python} setup.py build


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT --record=INSTALLED_FILES


%clean
rm -rf $RPM_BUILD_ROOT


%files -f INSTALLED_FILES


%changelog
* Fri Nov 4 2016 Daniel Vrcic <dvrcic@srce.hr> - 0.1.0-1%{?dist}
- initial version
