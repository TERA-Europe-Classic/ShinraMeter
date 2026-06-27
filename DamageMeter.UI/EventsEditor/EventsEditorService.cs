using Data;
using System;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;

namespace DamageMeter.UI.EventsEditor
{
    public static class EventsEditorService
    {
        private static readonly object Sync = new();
        private static Dispatcher? _dispatcher;
        private static bool _isStarting;
        private static EventsEditorWindow? _window;

        public static void Show()
        {
            var owner = Application.Current.Windows
                            .OfType<Window>()
                            .FirstOrDefault(w => w.IsActive)
                        ?? Application.Current.MainWindow;
            var ownerHandle = owner == null ? IntPtr.Zero : new WindowInteropHelper(owner).Handle;
            var topmost = owner?.Topmost ?? BasicTeraData.Instance.WindowData.Topmost;

            lock (Sync)
            {
                if (_isStarting) return;

                if (_dispatcher != null && !_dispatcher.HasShutdownStarted && !_dispatcher.HasShutdownFinished)
                {
                    _dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (_window == null) return;
                        _window.Topmost = topmost;
                        _window.Activate();
                    }));
                    return;
                }

                var thread = new Thread(() => RunEditor(ownerHandle, topmost))
                {
                    Name = "Shinra Events editor UI",
                    IsBackground = true
                };
                _isStarting = true;
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
            }
        }

        private static void RunEditor(IntPtr ownerHandle, bool topmost)
        {
            try
            {
                var dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

                var window = new EventsEditorWindow(ownerHandle, topmost);
                lock (Sync)
                {
                    _dispatcher = dispatcher;
                    _isStarting = false;
                    _window = window;
                }

                window.Closed += (_, _) =>
                {
                    lock (Sync)
                    {
                        _window = null;
                        _dispatcher = null;
                        _isStarting = false;
                    }

                    dispatcher.BeginInvokeShutdown(DispatcherPriority.Background);
                };

                window.Show();
                Dispatcher.Run();
            }
            catch
            {
                lock (Sync)
                {
                    _window = null;
                    _dispatcher = null;
                    _isStarting = false;
                }

                throw;
            }
        }
    }
}
