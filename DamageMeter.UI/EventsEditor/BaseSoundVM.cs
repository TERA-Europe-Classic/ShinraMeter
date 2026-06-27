using System.Windows.Threading;

namespace DamageMeter.UI
{
    public class BaseSoundVM : TSPropertyChanged
    {
        public BaseSoundVM() : base(Dispatcher.CurrentDispatcher)
        {
        }
    }
}
