using Nostrum.Extensions;
using Data;
using System;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Input;

namespace DamageMeter.UI.EventsEditor
{
    public partial class EventsEditorWindow : Window
    {
        public EventsEditorWindow() : this(IntPtr.Zero, BasicTeraData.Instance.WindowData.Topmost)
        {
        }

        public EventsEditorWindow(IntPtr ownerHandle, bool topmost)
        {
            InitializeComponent();

            if (ownerHandle != IntPtr.Zero)
            {
                new WindowInteropHelper(this).Owner = ownerHandle;
            }

            Topmost = topmost;
            ShowInTaskbar = ownerHandle == IntPtr.Zero;

            DataContext = new EventsEditorViewModel();
        }

        private void Drag(object sender, MouseButtonEventArgs e)
        {
            this.TryDragMove();
        }

        private void CloseWindow(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
